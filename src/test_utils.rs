//! Build small ELF objects and archives for unit tests.
//!
//! [`build_rel_object`] takes [`TestSymbol`] and [`TestRelocation`] records and
//! returns x86-64 ET_REL bytes. Archive builders wrap object bytes and can set
//! armap order; the thin archive builder writes only member paths. Tests can
//! thus check bad headers, unaligned members, and search order without running
//! an assembler.
//!
//! References: ELF gABI "ELF Header", "Sections", "Symbol Table", and "Relocation";
//! AMD64 psABI §4.4.1; GNU ar's member and index formats.

use elf::{Elf64SectionType, Elf64SymbolBinding, Elf64SymbolType, ElfFileType, ElfMachineType};

use crate::input::archive::reader::AR_FMAG;

const ELF_HEADER_SIZE: usize = 64;
const SECTION_HEADER_SIZE: usize = 64;
const SYMBOL_SIZE: usize = 24;
const RELA_SIZE: usize = 24;
const AR_MAGIC: &[u8; 8] = b"!<arch>\n";
const THIN_MAGIC: &[u8; 8] = b"!<thin>\n";
const AR_HEADER_SIZE: usize = 60;

/// Choose the input symbol fields a test needs; the builder adds its name to .strtab.
#[derive(Clone, Copy)]
pub(crate) struct TestSymbol<'a> {
    pub(crate) name: &'a str,
    pub(crate) binding: Elf64SymbolBinding,
    pub(crate) ty: Elf64SymbolType,
    pub(crate) section_idx: u16,
    pub(crate) value: u64,
    pub(crate) size: u64,
}

/// A RELA record that patches the test object's .text.
#[derive(Clone, Copy)]
pub(crate) struct TestRelocation {
    /// Byte offset within .text.
    pub(crate) offset: u64,
    /// Symbol index after the builder puts locals before globals.
    pub(crate) sym: u32,
    pub(crate) ty: u32,
    pub(crate) addend: i64,
}

/// Build x86-64 ET_REL bytes with five text bytes, chosen symbols, and optional RELA.
pub(crate) fn build_rel_object(
    symbols: &[TestSymbol<'_>],
    relocations: &[TestRelocation],
) -> Vec<u8> {
    let shstrtab = b"\0.shstrtab\0.text\0.rela.text\0.symtab\0.strtab\0";
    let text = [0x90u8, 0x90, 0x90, 0x90, 0xC3];

    let mut symbols = symbols.to_vec();
    symbols.sort_by_key(|symbol| usize::from(symbol.binding != Elf64SymbolBinding::STB_LOCAL));

    let mut strtab = vec![0];
    let mut name_offsets = Vec::with_capacity(symbols.len());
    for symbol in &symbols {
        if symbol.name.is_empty() {
            name_offsets.push(0);
        } else {
            let offset = strtab.len() as u32;
            strtab.extend_from_slice(symbol.name.as_bytes());
            strtab.push(0);
            name_offsets.push(offset);
        }
    }

    let local_count = symbols
        .iter()
        .take_while(|symbol| symbol.binding == Elf64SymbolBinding::STB_LOCAL)
        .count();
    let has_relocations = !relocations.is_empty();
    let section_count = if has_relocations { 6 } else { 5 };
    let symtab_section_idx = if has_relocations { 4 } else { 3 };
    let strtab_section_idx = if has_relocations { 5 } else { 4 };

    let shstrtab_offset = ELF_HEADER_SIZE;
    let text_offset = shstrtab_offset + shstrtab.len();
    let rela_offset = text_offset + text.len();
    let rela_size = RELA_SIZE * relocations.len();
    let symtab_offset = rela_offset + rela_size;
    let symtab_size = SYMBOL_SIZE * (symbols.len() + 1);
    let strtab_offset = symtab_offset + symtab_size;
    let shoff = strtab_offset + strtab.len();
    let file_size = shoff + SECTION_HEADER_SIZE * section_count;

    let mut out = vec![0u8; file_size];

    out[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    out[4] = 2;
    out[5] = 1;
    out[6] = 1;

    write_u16(&mut out, 16, ElfFileType::ET_REL.raw());
    write_u16(&mut out, 18, ElfMachineType::EM_X86_64.raw());
    write_u32(&mut out, 20, 1);
    write_u64(&mut out, 24, 0);
    write_u64(&mut out, 32, 0);
    write_u64(&mut out, 40, shoff as u64);
    write_u32(&mut out, 48, 0);
    write_u16(&mut out, 52, ELF_HEADER_SIZE as u16);
    write_u16(&mut out, 54, 0);
    write_u16(&mut out, 56, 0);
    write_u16(&mut out, 58, SECTION_HEADER_SIZE as u16);
    write_u16(&mut out, 60, section_count as u16);
    write_u16(&mut out, 62, 1);

    out[shstrtab_offset..shstrtab_offset + shstrtab.len()].copy_from_slice(shstrtab);
    out[text_offset..text_offset + text.len()].copy_from_slice(&text);
    out[strtab_offset..strtab_offset + strtab.len()].copy_from_slice(&strtab);

    for (i, symbol) in symbols.iter().enumerate() {
        let entry = symtab_offset + SYMBOL_SIZE * (i + 1);
        write_u32(&mut out, entry, name_offsets[i]);
        out[entry + 4] = ((symbol.binding as u8) << 4) | (symbol.ty as u8);
        out[entry + 5] = 0;
        write_u16(&mut out, entry + 6, symbol.section_idx);
        write_u64(&mut out, entry + 8, symbol.value);
        write_u64(&mut out, entry + 16, symbol.size);
    }

    for (i, relocation) in relocations.iter().enumerate() {
        let entry = rela_offset + RELA_SIZE * i;
        write_u64(&mut out, entry, relocation.offset);
        write_u64(
            &mut out,
            entry + 8,
            (u64::from(relocation.sym) << 32) | u64::from(relocation.ty),
        );
        write_i64(&mut out, entry + 16, relocation.addend);
    }

    let mut sh = shoff;

    sh += SECTION_HEADER_SIZE;

    write_u32(&mut out, sh, 1);
    write_u32(&mut out, sh + 4, Elf64SectionType::SHT_STRTAB.raw());
    write_u64(&mut out, sh + 24, shstrtab_offset as u64);
    write_u64(&mut out, sh + 32, shstrtab.len() as u64);
    write_u64(&mut out, sh + 48, 1);
    sh += SECTION_HEADER_SIZE;

    write_u32(&mut out, sh, 11);
    write_u32(&mut out, sh + 4, Elf64SectionType::SHT_PROGBITS.raw());
    write_u64(&mut out, sh + 8, 0x6);
    write_u64(&mut out, sh + 24, text_offset as u64);
    write_u64(&mut out, sh + 32, text.len() as u64);
    write_u64(&mut out, sh + 48, 16);
    sh += SECTION_HEADER_SIZE;

    if has_relocations {
        write_u32(&mut out, sh, 17);
        write_u32(&mut out, sh + 4, Elf64SectionType::SHT_RELA.raw());
        write_u64(&mut out, sh + 24, rela_offset as u64);
        write_u64(&mut out, sh + 32, rela_size as u64);
        write_u32(&mut out, sh + 40, symtab_section_idx);
        write_u32(&mut out, sh + 44, 2);
        write_u64(&mut out, sh + 48, 8);
        write_u64(&mut out, sh + 56, RELA_SIZE as u64);
        sh += SECTION_HEADER_SIZE;
    }

    write_u32(&mut out, sh, 28);
    write_u32(&mut out, sh + 4, Elf64SectionType::SHT_SYMTAB.raw());
    write_u64(&mut out, sh + 24, symtab_offset as u64);
    write_u64(&mut out, sh + 32, symtab_size as u64);
    write_u32(&mut out, sh + 40, strtab_section_idx);
    write_u32(&mut out, sh + 44, (local_count + 1) as u32);
    write_u64(&mut out, sh + 48, 8);
    write_u64(&mut out, sh + 56, SYMBOL_SIZE as u64);
    sh += SECTION_HEADER_SIZE;

    write_u32(&mut out, sh, 36);
    write_u32(&mut out, sh + 4, Elf64SectionType::SHT_STRTAB.raw());
    write_u64(&mut out, sh + 24, strtab_offset as u64);
    write_u64(&mut out, sh + 32, strtab.len() as u64);
    write_u64(&mut out, sh + 48, 1);

    out
}

/// Wrap member bytes in ar headers, adding a padding byte after odd lengths.
pub(crate) fn build_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::from(AR_MAGIC.as_slice());
    for &(name, payload) in members {
        push_member(&mut out, name, payload);
    }
    out
}

fn push_header(out: &mut Vec<u8>, name: &str, size: usize) {
    push_field(out, 16, name.as_bytes());
    push_field(out, 12, b"0");
    push_field(out, 6, b"0");
    push_field(out, 6, b"0");
    push_field(out, 8, b"100644");
    push_field(out, 10, size.to_string().as_bytes());
    out.extend_from_slice(&AR_FMAG);
}

fn write_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_i64(out: &mut [u8], offset: usize, value: i64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn push_field(out: &mut Vec<u8>, width: usize, value: &[u8]) {
    assert!(value.len() <= width);
    out.extend_from_slice(value);
    out.resize(out.len() + (width - value.len()), b' ');
}

fn push_member(out: &mut Vec<u8>, name: &str, payload: &[u8]) {
    push_header(out, name, payload.len());
    out.extend_from_slice(payload);
    if payload.len() % 2 != 0 {
        out.push(b'\n');
    }
}

/// Set armap order apart from file order so tests check which one search follows.
pub(crate) fn build_indexed_archive(
    members: &[(&str, &[u8])],
    entries: &[(&str, usize)],
) -> Vec<u8> {
    let names_size = entries
        .iter()
        .map(|(name, _)| name.len() + 1)
        .sum::<usize>();
    let table_size = 4 + entries.len() * 4 + names_size;
    let mut offset = AR_MAGIC.len() + AR_HEADER_SIZE + table_size + table_size % 2;
    let mut offsets = Vec::new();
    for (_, bytes) in members {
        offsets.push(offset as u32);
        offset += AR_HEADER_SIZE + bytes.len() + bytes.len() % 2;
    }
    let mut table = Vec::new();
    table.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (_, member_index) in entries {
        table.extend_from_slice(&offsets[*member_index].to_be_bytes());
    }
    for (name, _) in entries {
        table.extend_from_slice(name.as_bytes());
        table.push(0);
    }
    let mut indexed_members = vec![("/", table.as_slice())];
    indexed_members.extend_from_slice(members);
    build_archive(&indexed_members)
}

/// Build a thin archive: each member is a path and the size its header claims.
///
/// Like GNU ar, put every path in the `//` table and write no member data.
/// Armap entries name members by index; leave them empty to omit the armap.
pub(crate) fn build_thin_archive(members: &[(&str, usize)], entries: &[(&str, usize)]) -> Vec<u8> {
    let mut long_names = Vec::new();
    let mut name_offsets = Vec::new();
    for (path, _) in members {
        name_offsets.push(long_names.len());
        long_names.extend_from_slice(path.as_bytes());
        long_names.extend_from_slice(b"/\n");
    }
    let names_size = entries
        .iter()
        .map(|(name, _)| name.len() + 1)
        .sum::<usize>();
    let table_size = 4 + entries.len() * 4 + names_size;
    let mut offset = THIN_MAGIC.len() + AR_HEADER_SIZE + long_names.len() + long_names.len() % 2;
    if !entries.is_empty() {
        offset += AR_HEADER_SIZE + table_size + table_size % 2;
    }
    // Member headers follow one another with no data in between.
    let member_offsets = (0..members.len())
        .map(|index| (offset + index * AR_HEADER_SIZE) as u32)
        .collect::<Vec<_>>();

    let mut out = Vec::from(THIN_MAGIC.as_slice());
    if !entries.is_empty() {
        let mut table = Vec::new();
        table.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (_, member_index) in entries {
            table.extend_from_slice(&member_offsets[*member_index].to_be_bytes());
        }
        for (name, _) in entries {
            table.extend_from_slice(name.as_bytes());
            table.push(0);
        }
        push_member(&mut out, "/", &table);
    }
    push_member(&mut out, "//", &long_names);
    for ((_, size), name_offset) in members.iter().zip(name_offsets) {
        push_header(&mut out, &format!("/{name_offset}"), *size);
    }
    out
}
