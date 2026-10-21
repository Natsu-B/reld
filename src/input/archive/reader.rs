//! Read archive members, names, and the symbol index.
//!
//! [`ArchiveReader`] borrows ar bytes and returns [`ArchiveMember`] views and
//! [`ArchiveSymbol`] entries. [`MemberName`] tells short names, long-name table
//! offsets, BSD inline names, and special members apart.
//!
//! The symbol index, or armap, stores big-endian words even when its ELF members
//! use little-endian words. Members start on two-byte boundaries, so their ELF
//! records may lack Rust's native alignment. We follow GNU ar's name and index
//! formats and also accept BSD inline names.
//!
//! A thin archive starts with `!<thin>` instead of `!<arch>`. It keeps its armap
//! and name table, but each object member is only a header: the name is a path
//! to the object file, and the bytes stay in that file. Build systems use thin
//! archives to avoid copying every object. The header's size field still holds
//! the file's size, so we must not skip that many bytes to find the next header.
//!
//! References: [GNU ar](https://sourceware.org/binutils/docs/binutils/ar.html);
//! ELF gABI "ELF Header" applies to the bytes from [`ArchiveMember::object_bytes`].

use std::{cell::OnceCell, mem::size_of};

use anyhow::{Context, Result, bail, ensure};

/// Borrow the ar bytes and cache where the long-name table lives.
#[derive(Debug)]
pub(crate) struct ArchiveReader<'a> {
    data: &'a [u8],
    /// Object members name other files instead of holding bytes.
    thin: bool,
    long_name_table: OnceCell<Option<MemberSlice>>,
}

impl<'a> ArchiveReader<'a> {
    /// Check the magic, which also tells a thin archive from a regular one.
    pub(crate) fn new(data: &'a [u8]) -> Result<Self> {
        let thin = is_thin_archive(data);
        ensure!(
            thin || data.starts_with(AR_MAGIC),
            "invalid archive format: missing magic header"
        );

        Ok(Self {
            data,
            thin,
            long_name_table: OnceCell::new(),
        })
    }

    pub(crate) fn is_thin(&self) -> bool {
        self.thin
    }

    /// Visit members in file order, including the armap and long-name table.
    pub(crate) fn iter(&self) -> ArchiveIter<'_, 'a> {
        ArchiveIter {
            reader: self,
            offset: AR_MAGIC.len(),
        }
    }

    /// Visit object members without the armap and long-name table.
    pub(crate) fn object_members(&self) -> ArchiveObjectIter<'_, 'a> {
        ArchiveObjectIter { inner: self.iter() }
    }

    /// Find and cache the optional name table; borrow its bytes from the archive.
    pub(crate) fn long_name_table(&self) -> Result<Option<&'a [u8]>> {
        if let Some(cached) = self.long_name_table.get() {
            return Ok((*cached).map(|slice| self.slice(slice)));
        }

        let found = self.find_long_name_table()?;
        let _ = self.long_name_table.set(found);
        Ok(found.map(|slice| self.slice(slice)))
    }

    /// Read the armap in its stored order, including duplicate names.
    ///
    /// Its count and member offsets use big-endian words regardless of ELF byte order.
    pub(crate) fn symbol_table(&self) -> Result<Option<Vec<ArchiveSymbol<'a>>>> {
        for member in self.iter() {
            let member = member?;
            let width = match member.member_name()? {
                MemberName::SymbolTable => 4,
                MemberName::SymbolTable64 => 8,
                _ => continue,
            };
            return parse_symbol_table(member.payload()?, width).map(Some);
        }
        Ok(None)
    }

    fn find_long_name_table(&self) -> Result<Option<MemberSlice>> {
        for member in self.iter() {
            let member = member?;
            if matches!(member.member_name()?, MemberName::LongNameTable) {
                return Ok(Some(MemberSlice {
                    offset: member.payload_offset(),
                    size: member.size()?,
                }));
            }
        }

        Ok(None)
    }

    fn slice(&self, slice: MemberSlice) -> &'a [u8] {
        &self.data[slice.offset..slice.offset + slice.size]
    }
}

const AR_MAGIC: &[u8; 8] = b"!<arch>\n";
const THIN_MAGIC: &[u8; 8] = b"!<thin>\n";
pub(crate) const AR_FMAG: [u8; 2] = *b"`\n";
const AR_NAME_OFFSET: usize = std::mem::offset_of!(ArchiveMemberHeader, ar_name);
const AR_NAME_LEN: usize = size_of::<[u8; 16]>();
const AR_SIZE_OFFSET: usize = std::mem::offset_of!(ArchiveMemberHeader, ar_size);
const AR_SIZE_LEN: usize = size_of::<[u8; 10]>();
const AR_FMAG_OFFSET: usize = std::mem::offset_of!(ArchiveMemberHeader, ar_fmag);
const AR_FMAG_LEN: usize = size_of::<[u8; 2]>();

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ArchiveMemberHeader {
    ar_name: [u8; 16],
    ar_date: [u8; 12],
    ar_uid: [u8; 6],
    ar_gid: [u8; 6],
    ar_mode: [u8; 8],
    ar_size: [u8; 10],
    ar_fmag: [u8; 2],
}

/// Tell object names from ar's special index and name-table members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MemberName<'a> {
    /// `/` holds a count and member offsets as big-endian 32-bit words.
    SymbolTable,
    /// `/SYM64/` uses big-endian 64-bit words instead.
    SymbolTable64,
    /// `//` stores names that do not fit in the header.
    LongNameTable,
    /// Strip the trailing slash from an inline name.
    Short(&'a str),
    /// Byte offset in the GNU long-name table.
    LongNameOffset(usize),
    /// `#1/length` puts filename bytes at the start of the member data.
    BsdExtended(usize),
}

#[derive(Debug, Clone, Copy)]
struct MemberSlice {
    offset: usize,
    size: usize,
}

pub(crate) fn is_thin_archive(data: &[u8]) -> bool {
    data.starts_with(THIN_MAGIC)
}

/// A symbol name and the archive byte offset of its member header.
pub(crate) struct ArchiveSymbol<'a> {
    pub(crate) name: &'a str,
    /// Points to the member header, not its ELF data.
    pub(crate) member_offset: usize,
}

/// Keep the member's header offset, which the armap uses to find it.
#[derive(Debug)]
pub(crate) struct ArchiveMember<'a> {
    data: &'a [u8],
    offset: usize,
    /// Copied from the reader: a thin object member has no data here.
    thin: bool,
}

impl<'a> ArchiveMember<'a> {
    pub(crate) fn header_offset(&self) -> usize {
        self.offset
    }

    /// Read the decimal member size, including any BSD inline filename.
    pub(crate) fn size(&self) -> Result<usize> {
        Ok(to_decimal(self.header_field(AR_SIZE_OFFSET, AR_SIZE_LEN))? as usize)
    }

    pub(crate) fn payload_offset(&self) -> usize {
        self.offset + size_of::<ArchiveMemberHeader>()
    }

    /// Borrow the member data stored here after checking its bounds; this may
    /// include a filename. A thin object member stores none.
    fn payload(&self) -> Result<&'a [u8]> {
        let start = self.payload_offset();
        let end = start
            .checked_add(self.stored_size()?)
            .context("member payload end overflowed usize")?;

        self.data
            .get(start..end)
            .context("archive member payload is out of bounds")
    }

    /// Round past odd-sized data: ar puts the next header on an even byte boundary.
    pub(crate) fn next_offset(&self) -> Result<usize> {
        let size = self.stored_size()?;
        let payload_end = self
            .payload_offset()
            .checked_add(size)
            .context("member next offset overflowed usize")?;
        let padding = size % 2;

        payload_end
            .checked_add(padding)
            .context("member padding overflowed usize")
    }

    /// Read the header name format before following any long-name reference.
    pub(crate) fn member_name(&'a self) -> Result<MemberName<'a>> {
        let raw_name = std::str::from_utf8(self.header_field(AR_NAME_OFFSET, AR_NAME_LEN))
            .context("archive member name is not valid UTF-8")?;
        let raw_name = raw_name.trim_end_matches(' ');

        match raw_name {
            "/" => Ok(MemberName::SymbolTable),
            "/SYM64/" => Ok(MemberName::SymbolTable64),
            "//" => Ok(MemberName::LongNameTable),
            _ => {
                if let Some(rest) = raw_name.strip_prefix('/') {
                    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
                    let (offset, tail) = rest.split_at(digits);
                    // GNU ar writes `/offset:header` when a thin archive lists a
                    // member of a regular archive instead of an object file.
                    ensure!(
                        !(self.thin && tail.starts_with(':')),
                        "thin archive member {raw_name:?} is inside a nested archive, which is unsupported"
                    );
                    // GNU ar first writes the short name with its `/` ending, then
                    // writes the offset over bytes 1 to 14 only. A name of exactly
                    // 15 bytes thus leaves its `/` in the last byte, as in
                    // `/348           /`. Like BFD, read the digits and skip it.
                    ensure!(
                        !offset.is_empty() && tail.bytes().all(|byte| byte == b' ' || byte == b'/'),
                        "invalid long-name reference: {raw_name:?}"
                    );
                    return Ok(MemberName::LongNameOffset(offset.parse()?));
                }

                if let Some(len) = raw_name.strip_prefix("#1/") {
                    // A BSD name sits in the member data, which a thin archive lacks.
                    ensure!(
                        !self.thin,
                        "thin archive member uses a BSD inline name: {raw_name:?}"
                    );
                    ensure!(
                        !len.is_empty() && len.bytes().all(|byte| byte.is_ascii_digit()),
                        "invalid BSD extended name: {raw_name:?}"
                    );
                    return Ok(MemberName::BsdExtended(len.parse()?));
                }

                if let Some(short_name) = raw_name.strip_suffix('/') {
                    ensure!(!short_name.is_empty(), "archive member name is empty");
                    return Ok(MemberName::Short(short_name));
                }

                bail!("unsupported archive member name format: {raw_name:?}")
            }
        }
    }

    /// Read a GNU table name or BSD inline name for use in script patterns and errors.
    pub(crate) fn resolved_name(&self, long_names: Option<&[u8]>) -> Result<String> {
        match self.member_name()? {
            MemberName::Short(name) => Ok(name.to_string()),
            MemberName::LongNameOffset(offset) => {
                let long_names =
                    long_names.context("archive member refers to a missing long-name table")?;
                resolve_long_name(long_names, offset)
            }
            MemberName::BsdExtended(len) => {
                let payload = self.payload()?;
                ensure!(
                    len <= payload.len(),
                    "BSD extended name length {len} exceeds payload size {}",
                    payload.len()
                );
                let name = std::str::from_utf8(&payload[..len])
                    .context("BSD extended member name is not valid UTF-8")?;
                Ok(name.trim_end_matches('\0').to_string())
            }
            MemberName::SymbolTable | MemberName::SymbolTable64 | MemberName::LongNameTable => {
                bail!("special archive member does not have an object member name")
            }
        }
    }

    /// Skip any BSD inline filename so the returned bytes start at the ELF header.
    ///
    /// A thin archive member's bytes live in the file its name points to, so
    /// the caller must map that file instead.
    pub(crate) fn object_bytes(&self) -> Result<&'a [u8]> {
        ensure!(
            !self.thin,
            "thin archive member bytes are in a separate file"
        );
        let payload = self.payload()?;

        match self.member_name()? {
            MemberName::BsdExtended(len) => {
                ensure!(
                    len <= payload.len(),
                    "BSD extended name length {len} exceeds payload size {}",
                    payload.len()
                );
                Ok(&payload[len..])
            }
            MemberName::SymbolTable | MemberName::SymbolTable64 | MemberName::LongNameTable => {
                bail!("special archive member does not contain an ELF object")
            }
            MemberName::Short(_) | MemberName::LongNameOffset(_) => Ok(payload),
        }
    }

    fn is_special(&self) -> Result<bool> {
        Ok(matches!(
            self.member_name()?,
            MemberName::SymbolTable | MemberName::SymbolTable64 | MemberName::LongNameTable
        ))
    }

    /// Count the data bytes after the header in this file. A thin archive
    /// stores data only for its armap and name table.
    fn stored_size(&self) -> Result<usize> {
        if self.thin && !self.is_special()? {
            Ok(0)
        } else {
            self.size()
        }
    }

    fn header_field(&self, offset: usize, len: usize) -> &'a [u8] {
        let start = self.offset + offset;
        &self.data[start..start + len]
    }
}

/// Visit all members, including index and name-table members; report bad headers.
#[derive(Debug, Clone)]
pub(crate) struct ArchiveIter<'reader, 'data> {
    reader: &'reader ArchiveReader<'data>,
    offset: usize,
}

impl<'reader, 'data> Iterator for ArchiveIter<'reader, 'data> {
    type Item = Result<ArchiveMember<'data>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.reader.data.len() {
            return None;
        }

        if self.offset + size_of::<ArchiveMemberHeader>() > self.reader.data.len() {
            self.offset = self.reader.data.len();
            return Some(Err(anyhow::anyhow!(
                "invalid archive format: incomplete member header"
            )));
        }

        let member = ArchiveMember {
            data: self.reader.data,
            offset: self.offset,
            thin: self.reader.thin,
        };

        if member.header_field(AR_FMAG_OFFSET, AR_FMAG_LEN) != AR_FMAG.as_slice() {
            self.offset = self.reader.data.len();
            return Some(Err(anyhow::anyhow!(
                "invalid archive format: invalid member trailer"
            )));
        }

        let next_offset = match member.next_offset() {
            Ok(next_offset) => next_offset,
            Err(err) => {
                self.offset = self.reader.data.len();
                return Some(Err(err));
            }
        };

        self.offset = next_offset;
        Some(Ok(member))
    }
}

/// Skip archive tables so the caller sees only object members.
pub(crate) struct ArchiveObjectIter<'reader, 'data> {
    inner: ArchiveIter<'reader, 'data>,
}

impl<'reader, 'data> Iterator for ArchiveObjectIter<'reader, 'data> {
    type Item = Result<ArchiveMember<'data>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let member = self.inner.next()?;
            match member {
                Ok(member) => match member.is_special() {
                    Ok(true) => continue,
                    Ok(false) => return Some(Ok(member)),
                    Err(err) => return Some(Err(err)),
                },
                Err(err) => return Some(Err(err)),
            }
        }
    }
}

/// Read a name at a checked table offset; GNU ends each entry with `/\n`.
pub(crate) fn resolve_long_name(long_names: &[u8], offset: usize) -> Result<String> {
    ensure!(
        offset < long_names.len(),
        "long-name table offset out of bounds: {offset}"
    );

    let tail = &long_names[offset..];
    let end = tail
        .windows(2)
        .position(|window| window == b"/\n")
        .context("unterminated long-name table entry")?;

    Ok(std::str::from_utf8(&tail[..end])
        .context("long-name table entry is not valid UTF-8")?
        .to_string())
}

fn parse_symbol_table(data: &[u8], width: usize) -> Result<Vec<ArchiveSymbol<'_>>> {
    let read_word = |bytes: &[u8]| -> Result<usize> {
        let value = if width == 4 {
            u64::from(u32::from_be_bytes(bytes.try_into()?))
        } else {
            u64::from_be_bytes(bytes.try_into()?)
        };
        usize::try_from(value).context("archive symbol-table offset exceeds usize")
    };
    let count = read_word(
        data.get(..width)
            .context("truncated archive symbol-table count")?,
    )?;
    let names_offset = count
        .checked_add(1)
        .and_then(|count| count.checked_mul(width))
        .context("archive symbol-table size exceeds usize")?;
    let offsets = data
        .get(width..names_offset)
        .context("truncated archive symbol-table offsets")?;
    let mut names = data
        .get(names_offset..)
        .context("missing archive symbol-table names")?;
    let mut symbols = Vec::with_capacity(count);
    for offset in offsets.chunks_exact(width) {
        let end = names
            .iter()
            .position(|byte| *byte == 0)
            .context("unterminated archive symbol-table name")?;
        let name = std::str::from_utf8(&names[..end])
            .context("archive symbol-table name is not valid UTF-8")?;
        symbols.push(ArchiveSymbol {
            name,
            member_offset: read_word(offset)?,
        });
        names = &names[end + 1..];
    }
    Ok(symbols)
}

fn to_decimal(bytes: &[u8]) -> Result<u64> {
    let trimmed = std::str::from_utf8(bytes)
        .context("archive decimal field is not valid UTF-8")?
        .trim();
    Ok(trimmed.parse::<u64>()?)
}

#[cfg(test)]
mod tests {
    //! Check GNU/BSD names, armap word sizes, padding, and bad member ranges.

    use super::*;
    use crate::test_utils::{TestSymbol, build_archive, build_rel_object, build_thin_archive};
    use elf::{Elf64SymbolBinding, Elf64SymbolType};

    #[test]
    fn symbol_tables_preserve_order_and_duplicate_names_for_both_offset_widths() {
        for width in [4, 8] {
            let mut table = Vec::new();
            for word in [3u64, 0x120, 0x80, 0x120] {
                table.extend_from_slice(&word.to_be_bytes()[8 - width..]);
            }
            table.extend_from_slice(b"zeta\0alpha\0zeta\0");
            let archive = build_archive(&[(if width == 4 { "/" } else { "/SYM64/" }, &table)]);
            let reader = ArchiveReader::new(&archive).unwrap();
            let symbols = reader.symbol_table().unwrap().unwrap();
            assert_eq!(
                symbols
                    .iter()
                    .map(|symbol| (symbol.name, symbol.member_offset))
                    .collect::<Vec<_>>(),
                [("zeta", 0x120), ("alpha", 0x80), ("zeta", 0x120)]
            );
        }
    }

    #[test]
    fn truncated_symbol_tables_are_errors() {
        for table in [
            b"".as_slice(),
            &[0, 0, 0, 2, 0, 0, 0, 8],
            &[0, 0, 0, 1, 0, 0, 0, 8, b'x'],
        ] {
            let archive = build_archive(&[("/", table)]);
            assert!(
                ArchiveReader::new(&archive)
                    .unwrap()
                    .symbol_table()
                    .is_err()
            );
        }
    }

    #[test]
    fn magic_tells_thin_archives_apart() {
        assert!(!ArchiveReader::new(AR_MAGIC).unwrap().is_thin());
        assert!(ArchiveReader::new(THIN_MAGIC).unwrap().is_thin());
        assert!(ArchiveReader::new(b"\x7FELF").is_err());
    }

    #[test]
    fn thin_member_headers_follow_each_other() {
        // The size fields claim odd file sizes, but no member data follows.
        let archive =
            build_thin_archive(&[("../obj/a.o", 1201), ("b.o", 7)], &[("b", 1), ("a", 0)]);
        let reader = ArchiveReader::new(&archive).unwrap();
        let long_names = reader.long_name_table().unwrap();
        let members = reader
            .object_members()
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        assert_eq!(
            members
                .iter()
                .map(|member| member.resolved_name(long_names).unwrap())
                .collect::<Vec<_>>(),
            ["../obj/a.o", "b.o"]
        );
        assert_eq!(members[0].size().unwrap(), 1201);
        assert!(members[0].object_bytes().is_err());
        let symbols = reader.symbol_table().unwrap().unwrap();
        assert_eq!(symbols[0].member_offset, members[1].header_offset());
        assert_eq!(symbols[1].member_offset, members[0].header_offset());
    }

    #[test]
    fn long_name_reference_may_keep_a_stray_slash() {
        // GNU ar leaves this `/` behind for a 15-byte name such as gconv_builtin.o.
        let mut archive = Vec::from(THIN_MAGIC.as_slice());
        push_member_with_trailer(&mut archive, "//", b"../gconv_builtin.o/\n", AR_FMAG);
        push_member_with_trailer(&mut archive, "/0             /", &[], AR_FMAG);
        let reader = ArchiveReader::new(&archive).unwrap();
        let member = reader.object_members().next().unwrap().unwrap();

        assert_eq!(member.member_name().unwrap(), MemberName::LongNameOffset(0));
        assert_eq!(
            member
                .resolved_name(reader.long_name_table().unwrap())
                .unwrap(),
            "../gconv_builtin.o"
        );
    }

    #[test]
    fn thin_archives_reject_member_names_that_need_data() {
        for (name, message) in [("#1/5", "BSD inline name"), ("/0:180", "nested archive")] {
            let mut archive = Vec::from(THIN_MAGIC.as_slice());
            push_member_with_trailer(&mut archive, name, &[], AR_FMAG);
            let reader = ArchiveReader::new(&archive).unwrap();
            let error = reader.iter().next().unwrap().unwrap_err();
            assert!(error.to_string().contains(message), "{name}: {error}");
        }
    }

    #[test]
    fn short_name_member_resolves() {
        let payload = [1u8, 2, 3];
        let archive = build_archive(&[("foo.o/", &payload)]);
        let reader = ArchiveReader::new(&archive).unwrap();
        let member = reader.object_members().next().unwrap().unwrap();

        assert_eq!(member.member_name().unwrap(), MemberName::Short("foo.o"));
        assert_eq!(member.resolved_name(None).unwrap(), "foo.o");
        assert_eq!(member.object_bytes().unwrap(), payload);
    }

    #[test]
    fn odd_sized_member_skips_padding() {
        let first = [1u8, 2, 3];
        let second = [4u8, 5, 6, 7];
        let archive = build_archive(&[("one.o/", &first), ("two.o/", &second)]);
        let reader = ArchiveReader::new(&archive).unwrap();
        let mut members = reader.object_members();

        let first_member = members.next().unwrap().unwrap();
        let second_member = members.next().unwrap().unwrap();

        assert_eq!(first_member.object_bytes().unwrap(), first);
        assert_eq!(second_member.resolved_name(None).unwrap(), "two.o");
        assert_eq!(second_member.object_bytes().unwrap(), second);
        assert!(members.next().is_none());
    }

    #[test]
    fn long_name_table_resolves_offsets() {
        let long_names = b"very_long_member_name.o/\n";
        let object = build_rel_object(
            &[TestSymbol {
                name: "foo",
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        );
        let archive = build_archive(&[("//", long_names), ("/0", &object)]);
        let reader = ArchiveReader::new(&archive).unwrap();
        let member = reader.object_members().next().unwrap().unwrap();

        assert_eq!(reader.long_name_table().unwrap().unwrap(), long_names);
        assert_eq!(
            member
                .resolved_name(reader.long_name_table().unwrap())
                .unwrap(),
            "very_long_member_name.o"
        );
    }

    #[test]
    fn bsd_extended_name_resolves() {
        let object = build_rel_object(
            &[TestSymbol {
                name: "foo",
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        );
        let name = b"bsd_member_name.o";
        let mut payload = name.to_vec();
        payload.extend_from_slice(&object);

        let archive = build_archive(&[("#1/17", &payload)]);
        let reader = ArchiveReader::new(&archive).unwrap();
        let member = reader.object_members().next().unwrap().unwrap();

        assert_eq!(member.resolved_name(None).unwrap(), "bsd_member_name.o");
        assert_eq!(member.object_bytes().unwrap(), object);
    }

    #[test]
    fn special_members_are_skipped_from_object_iteration() {
        let object = build_rel_object(
            &[TestSymbol {
                name: "foo",
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        );
        let archive = build_archive(&[
            ("/", b"symtab"),
            ("/SYM64/", b"symtab64"),
            ("//", b"foo.o/\n"),
            ("foo.o/", &object),
        ]);
        let reader = ArchiveReader::new(&archive).unwrap();
        let members = reader
            .object_members()
            .map(|member| {
                member
                    .unwrap()
                    .resolved_name(reader.long_name_table().unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>();

        assert_eq!(members, vec!["foo.o".to_string()]);
        assert_eq!(reader.long_name_table().unwrap().unwrap(), b"foo.o/\n");
    }

    #[test]
    fn invalid_trailer_is_rejected() {
        let object = build_rel_object(
            &[TestSymbol {
                name: "foo",
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        );
        let mut archive = Vec::from(AR_MAGIC.as_slice());
        push_member_with_trailer(&mut archive, "foo.o/", &object, *b"!!");
        let reader = ArchiveReader::new(&archive).unwrap();
        let err = reader.iter().next().unwrap().unwrap_err();

        assert!(err.to_string().contains("invalid member trailer"));
    }

    fn push_field(out: &mut Vec<u8>, width: usize, value: &[u8]) {
        assert!(value.len() <= width);
        out.extend_from_slice(value);
        out.resize(out.len() + (width - value.len()), b' ');
    }

    fn push_member_with_trailer(out: &mut Vec<u8>, name: &str, payload: &[u8], trailer: [u8; 2]) {
        push_field(out, 16, name.as_bytes());
        push_field(out, 12, b"0");
        push_field(out, 6, b"0");
        push_field(out, 6, b"0");
        push_field(out, 8, b"100644");
        push_field(out, 10, payload.len().to_string().as_bytes());
        out.extend_from_slice(&trailer);
        out.extend_from_slice(payload);
        if payload.len() % 2 != 0 {
            out.push(b'\n');
        }
    }
}
