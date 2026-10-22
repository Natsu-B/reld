//! Give each needed symbol a slot in the Global Offset Table (GOT).
//!
//! [`Got::collect`] takes kept relocations and chosen definitions and returns a
//! [`Got`] plan. [`GotEntry`] says what a slot will hold: a symbol address, a TLS
//! offset from the thread pointer, or an IFUNC result set by startup.
//!
//! We key slots by [`SymbolId`] and purpose. References to one global share a
//! slot; equally named local symbols in different files do not. GOTPCRELX can
//! allow instruction rewrites, but its ordinary GOT formula still works without
//! them. We leave those instructions as they are.
//!
//! References: AMD64 psABI §4.4.1, §5.2 (Global Offset Table), and appendix B.2.
//! GNU static IFUNC startup fills the result slots.

use std::collections::HashMap;

use anyhow::{Context, Result};
use elf::x86_64::X86_64RelocationType;

use crate::{
    input::object::{InputSection, ObjectRelocation},
    symbols::{SymbolId, SymbolTable},
};

use super::SyntheticSection;

const ENTRY_SIZE: u64 = 8;

/// Assign eight-byte slots in first-reference order, sharing equal symbol-and-purpose keys.
#[derive(Default)]
pub(crate) struct Got {
    entries: Vec<GotEntry>,
    offsets: HashMap<GotEntry, u64>,
}

/// The same symbol may need distinct slots for an address and a TLS offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum GotEntry {
    Address(SymbolId),
    TpOff(SymbolId),
    /// Leave zero until startup calls the resolver and writes the result.
    Ifunc(SymbolId),
}

impl Got {
    pub(crate) fn needs_entry(ty: u32) -> bool {
        matches!(
            X86_64RelocationType::try_from(ty),
            Ok(X86_64RelocationType::GotPcRel
                | X86_64RelocationType::GotPcRelX
                | X86_64RelocationType::RexGotPcRelX
                | X86_64RelocationType::GotTpOff)
        )
    }

    /// Read kept relocations, check their symbol types, and assign GOT slots.
    pub(crate) fn collect(relocations: &[ObjectRelocation], symbols: &SymbolTable) -> Result<Self> {
        let mut got = Self::default();
        for relocation in relocations {
            let ty = X86_64RelocationType::try_from(relocation.info)?;
            if ty == X86_64RelocationType::None {
                continue;
            }
            let symbol = symbols.input(relocation.file_id, relocation.info.sym)?;
            symbols.get(symbol).validate_relocation(ty)?;
            if symbols.get(symbol).is_ifunc() {
                got.allocate(GotEntry::Ifunc(symbol));
            } else if Self::needs_entry(relocation.info.ty) {
                let entry = if ty == X86_64RelocationType::GotTpOff {
                    GotEntry::TpOff(symbol)
                } else {
                    GotEntry::Address(symbol)
                };
                got.allocate(entry);
                pr_debug!(
                    "GOT entry for {} ({:?})",
                    symbols.get(symbol).name,
                    symbols.get(symbol).ty
                );
            }
        }
        Ok(got)
    }

    fn allocate(&mut self, entry: GotEntry) {
        if !self.offsets.contains_key(&entry) {
            let offset = self.entries.len() as u64 * ENTRY_SIZE;
            self.offsets.insert(entry, offset);
            self.entries.push(entry);
        }
    }

    /// Visit slots with byte offsets in the order they were first needed.
    pub(crate) fn entries(&self) -> impl Iterator<Item = (GotEntry, u64)> + '_ {
        self.entries
            .iter()
            .enumerate()
            .map(|(index, entry)| (*entry, index as u64 * ENTRY_SIZE))
    }

    pub(crate) fn offset(&self, entry: GotEntry) -> Result<u64> {
        self.offsets
            .get(&entry)
            .copied()
            .context("missing GOT entry for resolved symbol")
    }

    /// Reserve bytes here; fill slot values only after layout knows addresses.
    pub(crate) fn section(&self) -> InputSection<'static> {
        SyntheticSection::Got.section(self.entries.len() as u64 * ENTRY_SIZE)
    }
}

#[cfg(test)]
mod tests {
    //! Check which references share slots and which need distinct TLS or IFUNC slots.

    use super::*;
    use crate::{
        input::{FileId, FileNames, object},
        symbols,
        synthetic::Iplt,
        test_utils::{TestRelocation, TestSymbol, build_rel_object},
    };
    use elf::{Elf64SectionFlags, Elf64SymbolBinding, Elf64SymbolType};

    fn symbol(binding: Elf64SymbolBinding, section_idx: u16) -> TestSymbol<'static> {
        TestSymbol {
            name: "foo",
            binding,
            ty: Elf64SymbolType::STT_OBJECT,
            section_idx,
            value: 0,
            size: 0,
        }
    }

    #[test]
    fn deduplicates_all_gotpcrel_kinds_by_resolved_symbol_across_files() {
        let definition = build_rel_object(&[symbol(Elf64SymbolBinding::STB_GLOBAL, 2)], &[]);
        let reference = build_rel_object(
            &[symbol(Elf64SymbolBinding::STB_GLOBAL, 0)],
            &[9, 41, 42].map(|ty| TestRelocation {
                offset: 0,
                sym: 1,
                ty,
                addend: -4,
            }),
        );
        let mut objects = [
            object::parse(
                &definition,
                "def.o".to_string(),
                FileId::InputObject { input_index: 0 },
            )
            .unwrap(),
            object::parse(
                &reference,
                "a.o".to_string(),
                FileId::InputObject { input_index: 1 },
            )
            .unwrap(),
            object::parse(
                &reference,
                "b.o".to_string(),
                FileId::InputObject { input_index: 2 },
            )
            .unwrap(),
        ];
        let symbols = objects
            .iter_mut()
            .flat_map(|object| std::mem::take(&mut object.symbols))
            .collect::<Vec<_>>();
        let relocations = objects
            .into_iter()
            .flat_map(|object| object.relocations)
            .collect::<Vec<_>>();
        let symbols = symbols::resolve_inputs(&symbols, &[], &FileNames::default()).unwrap();
        let got = Got::collect(&relocations, &symbols).unwrap();
        assert_eq!(got.entries().count(), 1);
        assert_eq!(got.section().size, 8);
        assert_eq!(got.section().align, 8);
        let flags = got.section().flags;
        assert_eq!(flags.get(Elf64SectionFlags::SHF_ALLOC), 1);
        assert_eq!(flags.get(Elf64SectionFlags::SHF_WRITE), 1);
        for file in 0..3 {
            assert_eq!(
                got.offset(GotEntry::Address(
                    symbols
                        .input(FileId::InputObject { input_index: file }, 1)
                        .unwrap()
                ))
                .unwrap(),
                0
            );
        }
    }

    #[test]
    fn local_symbols_with_equal_names_and_indexes_have_separate_slots() {
        let bytes = build_rel_object(
            &[symbol(Elf64SymbolBinding::STB_LOCAL, 2)],
            &[TestRelocation {
                offset: 0,
                sym: 1,
                ty: 42,
                addend: -4,
            }],
        );
        let mut objects = [
            object::parse(
                &bytes,
                "a.o".to_string(),
                FileId::InputObject { input_index: 0 },
            )
            .unwrap(),
            object::parse(
                &bytes,
                "b.o".to_string(),
                FileId::InputObject { input_index: 1 },
            )
            .unwrap(),
        ];
        let symbols = objects
            .iter_mut()
            .flat_map(|object| std::mem::take(&mut object.symbols))
            .collect::<Vec<_>>();
        let relocations = objects
            .into_iter()
            .flat_map(|object| object.relocations)
            .collect::<Vec<_>>();
        let symbols = symbols::resolve_inputs(&symbols, &[], &FileNames::default()).unwrap();
        let got = Got::collect(&relocations, &symbols).unwrap();
        assert_eq!(got.entries().count(), 2);
        assert_eq!(got.section().size, 16);
        assert_eq!(
            got.offset(GotEntry::Address(
                symbols
                    .input(FileId::InputObject { input_index: 0 }, 1)
                    .unwrap()
            ))
            .unwrap(),
            0
        );
        assert_eq!(
            got.offset(GotEntry::Address(
                symbols
                    .input(FileId::InputObject { input_index: 1 }, 1)
                    .unwrap()
            ))
            .unwrap(),
            8
        );
    }

    #[test]
    fn tls_offsets_are_deduplicated_separately_from_addresses() {
        let bytes = build_rel_object(&[symbol(Elf64SymbolBinding::STB_GLOBAL, 2)], &[]);
        let object = object::parse(
            &bytes,
            "a.o".to_string(),
            FileId::InputObject { input_index: 0 },
        )
        .unwrap();
        let symbols = symbols::resolve_inputs(&object.symbols, &[], &FileNames::default()).unwrap();
        let id = symbols
            .input(FileId::InputObject { input_index: 0 }, 1)
            .unwrap();
        let mut got = Got::default();
        for _ in 0..2 {
            got.allocate(GotEntry::Address(id));
            got.allocate(GotEntry::TpOff(id));
        }
        assert_eq!(got.offset(GotEntry::Address(id)).unwrap(), 0);
        assert_eq!(got.offset(GotEntry::TpOff(id)).unwrap(), 8);
        assert_eq!(got.section().size, 16);
    }

    #[test]
    fn ifunc_references_share_one_slot_stub_and_irelative_record() {
        let definition = build_rel_object(
            &[TestSymbol {
                ty: Elf64SymbolType::STT_GNU_IFUNC,
                ..symbol(Elf64SymbolBinding::STB_GLOBAL, 2)
            }],
            &[],
        );
        let reference = build_rel_object(
            &[TestSymbol {
                ty: Elf64SymbolType::STT_FUNC,
                ..symbol(Elf64SymbolBinding::STB_GLOBAL, 0)
            }],
            &[1, 2, 4, 9, 10, 11, 41, 42].map(|ty| TestRelocation {
                offset: 0,
                sym: 1,
                ty,
                addend: -4,
            }),
        );
        let definition = object::parse(
            &definition,
            "def.o".to_string(),
            FileId::InputObject { input_index: 0 },
        )
        .unwrap();
        let reference = object::parse(
            &reference,
            "ref.o".to_string(),
            FileId::InputObject { input_index: 1 },
        )
        .unwrap();
        let symbols = definition
            .symbols
            .into_iter()
            .chain(reference.symbols)
            .collect::<Vec<_>>();
        let symbols = symbols::resolve_inputs(&symbols, &[], &FileNames::default()).unwrap();
        let id = symbols
            .input(FileId::InputObject { input_index: 0 }, 1)
            .unwrap();
        assert_eq!(
            symbols
                .input(FileId::InputObject { input_index: 1 }, 1)
                .unwrap(),
            id
        );
        let got = Got::collect(&reference.relocations, &symbols).unwrap();
        assert_eq!(
            got.entries().collect::<Vec<_>>(),
            vec![(GotEntry::Ifunc(id), 0)]
        );
        let [stubs, relas] = Iplt::new(&got).sections();
        assert_eq!(stubs.size, 16);
        assert_eq!(stubs.align, 16);
        assert_eq!(stubs.flags.get(Elf64SectionFlags::SHF_EXECINSTR), 1);
        assert_eq!(relas.size, 24);
        assert_eq!(relas.align, 8);
        assert_eq!(relas.flags.get(Elf64SectionFlags::SHF_ALLOC), 1);
    }
}
