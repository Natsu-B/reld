//! Pick one definition for each global name before addresses exist.
//!
//! [`resolve`] takes a [`SectionMapping`] and returns a [`SymbolTable`];
//! [`FileNames`] only lets errors name the file the user gave.
//! References to one global share a [`SymbolId`]; local symbols stay tied to
//! their input file. A strong definition beats a weak one. Two strong definitions
//! or a missing strong definition cause an error; a missing weak one gets zero.
//!
//! GNU ld's PROVIDE defines a script name only if an input refers to it and no
//! input or plain script assignment defines it. PROVIDE_HIDDEN makes that symbol
//! local in static output. This linker rejects COMMON storage.
//!
//! References: ELF gABI "Symbol Binding", "Symbol Type", and "Symbol Value";
//! AMD64 psABI §4.3; GNU ld [`PROVIDE`](https://sourceware.org/binutils/docs/ld/PROVIDE.html)
//! and PROVIDE_HIDDEN.

use std::collections::{HashMap, HashSet};

use anyhow::{Result, bail, ensure};
use elf::{Elf64SymbolBinding, Elf64SymbolInfo, Elf64SymbolSectionIdx, Elf64SymbolType};

use super::table::{Definition, SymbolId, SymbolTable};
use crate::{
    input::{FileNames, object::ObjectSymbol},
    script::{
        ast::{Assignment, AssignmentKind},
        mapping::SectionMapping,
    },
};

/// Pick definitions from the mapped inputs and script assignments, before layout.
pub(crate) fn resolve(mapping: &SectionMapping, names: &FileNames) -> Result<SymbolTable> {
    resolve_inputs(&mapping.symbols, &mapping.assignments(), names)
}

/// Give each global name one definition and keep local symbols separate.
///
/// Strong definitions beat weak ones. Reject duplicate strong definitions and
/// missing strong references. Pick needed PROVIDE assignments here; layout will
/// compute their values. Missing weak symbols get a definition whose value is zero.
pub(crate) fn resolve_inputs(
    symbols: &[ObjectSymbol],
    assignments: &[&Assignment],
    names: &FileNames,
) -> Result<SymbolTable> {
    pr_debug!("Resolving symbol names...");
    let mut table = SymbolTable::default();
    let mut definitions: HashMap<&str, &ObjectSymbol> = HashMap::new();
    let mut references = HashSet::new();
    for symbol in symbols {
        let binding = symbol_binding(symbol, names)?;
        ensure!(
            symbol.section_idx != Elf64SymbolSectionIdx::Common,
            "unsupported common symbol: {} in file: {}",
            symbol.name,
            names.show(symbol.file_id)
        );
        if symbol.name.is_empty() || binding == Elf64SymbolBinding::STB_LOCAL {
            continue;
        }
        if symbol.section_idx == Elf64SymbolSectionIdx::Undefined {
            references.insert(symbol.name);
        } else if let Some(old) = definitions.get(symbol.name) {
            let weak = symbol.info.get_enum(Elf64SymbolInfo::st_bind)
                == Some(Elf64SymbolBinding::STB_WEAK);
            let old_weak =
                old.info.get_enum(Elf64SymbolInfo::st_bind) == Some(Elf64SymbolBinding::STB_WEAK);
            if !weak && !old_weak {
                bail!(
                    "multiple definition of symbol: {} in files: {} and {}",
                    symbol.name,
                    names.show(symbol.file_id),
                    names.show(old.file_id)
                );
            }
            if !weak {
                definitions.insert(symbol.name, symbol);
            }
        } else {
            definitions.insert(symbol.name, symbol);
        }
    }

    // Keep input order so each chosen definition gets a repeatable SymbolId.
    for symbol in symbols {
        if definitions
            .get(symbol.name)
            .is_some_and(|winner| std::ptr::eq(*winner, symbol))
        {
            let id = insert_input(&mut table, symbol, names)?;
            table.by_name.insert(symbol.name.to_string(), id);
        }
    }
    // Like GNU ld, a plain script definition beats PROVIDE even if PROVIDE
    // appears first. Pick plain definitions before testing PROVIDE's rule.
    for assignment in assignments {
        if assignment.name == "." || assignment.kind != AssignmentKind::Define {
            continue;
        }
        ensure!(
            !definitions.contains_key(assignment.name.as_str()),
            "{}: multiple definition of symbol: {} in input and linker script",
            assignment.location,
            assignment.name
        );
        if !table.by_name.contains_key(&assignment.name) {
            let id = table.insert(
                &assignment.name,
                Some(Elf64SymbolType::STT_NOTYPE),
                Elf64SymbolBinding::STB_GLOBAL,
                0,
                0,
                Definition::Script { provide: None },
            );
            table.by_name.insert(assignment.name.clone(), id);
        }
    }
    for assignment in assignments {
        if assignment.kind != AssignmentKind::Define
            && references.contains(assignment.name.as_str())
            && !table.by_name.contains_key(&assignment.name)
        {
            // There is no dynamic lookup in this static image. Like GNU ld,
            // write hidden script symbols as locals in .symtab.
            let binding = if assignment.kind == AssignmentKind::ProvideHidden {
                Elf64SymbolBinding::STB_LOCAL
            } else {
                Elf64SymbolBinding::STB_GLOBAL
            };
            let id = table.insert(
                &assignment.name,
                Some(Elf64SymbolType::STT_NOTYPE),
                binding,
                0,
                0,
                Definition::Script {
                    provide: Some(assignment.location),
                },
            );
            table.by_name.insert(assignment.name.clone(), id);
        }
    }
    // Check missing strong names before adding weak-zero entries. Otherwise
    // a weak entry could mask a strong reference that needs an error.
    for symbol in symbols {
        if !symbol.name.is_empty()
            && symbol.section_idx == Elf64SymbolSectionIdx::Undefined
            && symbol.info.get_enum(Elf64SymbolInfo::st_bind)
                == Some(Elf64SymbolBinding::STB_GLOBAL)
            && !table.by_name.contains_key(symbol.name)
        {
            bail!(
                "undefined symbol: {} in file: {}",
                symbol.name,
                names.show(symbol.file_id)
            );
        }
    }
    for symbol in symbols {
        let binding = symbol.info.get_enum(Elf64SymbolInfo::st_bind);
        let id = if !symbol.name.is_empty() && binding != Some(Elf64SymbolBinding::STB_LOCAL) {
            if let Some(id) = table.by_name.get(symbol.name) {
                *id
            } else if binding == Some(Elf64SymbolBinding::STB_WEAK) {
                let id = table.insert(
                    symbol.name,
                    symbol.info.get_enum(Elf64SymbolInfo::st_type),
                    Elf64SymbolBinding::STB_WEAK,
                    symbol.size,
                    symbol.other,
                    Definition::UndefinedWeak,
                );
                table.by_name.insert(symbol.name.to_string(), id);
                id
            } else {
                bail!(
                    "undefined symbol: {} in file: {}",
                    symbol.name,
                    names.show(symbol.file_id)
                );
            }
        } else if symbol.section_idx == Elf64SymbolSectionIdx::Undefined {
            // ELF's null symbol supplies zero without a defining section.
            table.insert(
                "",
                None,
                Elf64SymbolBinding::STB_LOCAL,
                0,
                0,
                Definition::UndefinedWeak,
            )
        } else {
            insert_input(&mut table, symbol, names)?
        };
        table.by_input.insert((symbol.file_id, symbol.idx), id);
    }
    Ok(table)
}

fn symbol_binding(symbol: &ObjectSymbol, names: &FileNames) -> Result<Elf64SymbolBinding> {
    match symbol.info.get_enum(Elf64SymbolInfo::st_bind) {
        Some(
            binding @ (Elf64SymbolBinding::STB_LOCAL
            | Elf64SymbolBinding::STB_GLOBAL
            | Elf64SymbolBinding::STB_WEAK),
        ) => Ok(binding),
        _ => bail!(
            "unsupported symbol binding {} for symbol: {} in file: {} (expected LOCAL, GLOBAL, or WEAK)",
            symbol.info.get(Elf64SymbolInfo::st_bind),
            symbol.name,
            names.show(symbol.file_id)
        ),
    }
}

fn insert_input(
    table: &mut SymbolTable,
    symbol: &ObjectSymbol,
    names: &FileNames,
) -> Result<SymbolId> {
    Ok(table.insert(
        symbol.name,
        symbol.info.get_enum(Elf64SymbolInfo::st_type),
        symbol_binding(symbol, names)?,
        symbol.size,
        symbol.other,
        Definition::Input {
            file_id: symbol.file_id,
            section_idx: symbol.section_idx,
            value: symbol.value,
        },
    ))
}

#[cfg(test)]
mod tests {
    //! Check strong/weak choices, PROVIDE rules, and missing weak values.

    use super::*;
    use crate::{
        input::FileId,
        script::{ast::Statement, parser},
    };

    fn symbol(
        file: usize,
        name: &'static str,
        binding: Elf64SymbolBinding,
        ty: Elf64SymbolType,
        section_idx: Elf64SymbolSectionIdx,
    ) -> ObjectSymbol<'static> {
        ObjectSymbol {
            file_id: FileId::InputObject { input_index: file },
            idx: 1,
            name,
            info: Elf64SymbolInfo::from_bits(((binding as u8) << 4) | ty as u8),
            section_idx,
            value: 42,
            size: 0,
            other: 0,
        }
    }

    #[test]
    fn unsupported_bindings_report_an_error_instead_of_panicking() {
        for binding in [3, Elf64SymbolBinding::STB_LOOS as u8] {
            let mut input = symbol(
                0,
                "unsupported",
                Elf64SymbolBinding::STB_GLOBAL,
                Elf64SymbolType::STT_OBJECT,
                Elf64SymbolSectionIdx::AbsoluteSymbols,
            );
            input.info = input.info.set(Elf64SymbolInfo::st_bind, binding);
            let error = resolve_inputs(&[input], &[], &FileNames::default())
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains(&format!("unsupported symbol binding {binding}")));
            assert!(error.contains("unsupported"));
            assert!(error.contains("file:"));
        }
    }

    #[test]
    fn selects_strong_definition_and_preserves_its_type_before_layout() {
        let weak = symbol(
            0,
            "foo",
            Elf64SymbolBinding::STB_WEAK,
            Elf64SymbolType::STT_FUNC,
            Elf64SymbolSectionIdx::AbsoluteSymbols,
        );
        let strong = symbol(
            1,
            "foo",
            Elf64SymbolBinding::STB_GLOBAL,
            Elf64SymbolType::STT_GNU_IFUNC,
            Elf64SymbolSectionIdx::AbsoluteSymbols,
        );
        let reference = symbol(
            2,
            "foo",
            Elf64SymbolBinding::STB_GLOBAL,
            Elf64SymbolType::STT_NOTYPE,
            Elf64SymbolSectionIdx::Undefined,
        );
        let symbols = vec![weak, strong, reference];
        let table = resolve_inputs(&symbols, &[], &FileNames::default()).unwrap();
        let id = table
            .input(FileId::InputObject { input_index: 0 }, 1)
            .unwrap();
        assert_eq!(
            table
                .input(FileId::InputObject { input_index: 1 }, 1)
                .unwrap(),
            id
        );
        assert_eq!(
            table
                .input(FileId::InputObject { input_index: 2 }, 1)
                .unwrap(),
            id
        );
        assert_eq!(table.get(id).ty, Some(Elf64SymbolType::STT_GNU_IFUNC));
        assert_eq!(table.get(id).address.get(), None);
        table
            .assign_addresses(&[], &HashMap::new(), &HashMap::new())
            .unwrap();
        assert_eq!(table.get(id).address.get(), Some(&42));
    }

    #[test]
    fn undefined_weak_symbols_share_a_zero_definition() {
        let symbols = [0, 1].map(|file| {
            symbol(
                file,
                "optional",
                Elf64SymbolBinding::STB_WEAK,
                Elf64SymbolType::STT_NOTYPE,
                Elf64SymbolSectionIdx::Undefined,
            )
        });
        let table = resolve_inputs(&symbols, &[], &FileNames::default()).unwrap();
        let id = table
            .input(FileId::InputObject { input_index: 0 }, 1)
            .unwrap();
        assert_eq!(
            table
                .input(FileId::InputObject { input_index: 1 }, 1)
                .unwrap(),
            id
        );
        table
            .assign_addresses(&[], &HashMap::new(), &HashMap::new())
            .unwrap();
        assert_eq!(table.get(id).address.get(), Some(&0));
    }

    #[test]
    fn weak_reference_does_not_hide_an_undefined_strong_reference() {
        for bindings in [
            [Elf64SymbolBinding::STB_WEAK, Elf64SymbolBinding::STB_GLOBAL],
            [Elf64SymbolBinding::STB_GLOBAL, Elf64SymbolBinding::STB_WEAK],
        ] {
            let symbols = bindings
                .into_iter()
                .enumerate()
                .map(|(file, binding)| {
                    symbol(
                        file,
                        "missing",
                        binding,
                        Elf64SymbolType::STT_NOTYPE,
                        Elf64SymbolSectionIdx::Undefined,
                    )
                })
                .collect::<Vec<_>>();
            let error = resolve_inputs(&symbols, &[], &FileNames::default())
                .err()
                .unwrap();
            assert!(error.to_string().contains("undefined symbol: missing"));
        }
    }

    #[test]
    fn duplicate_strong_definitions_fail_before_layout() {
        let symbols = [0, 1].map(|file| {
            symbol(
                file,
                "duplicate",
                Elf64SymbolBinding::STB_GLOBAL,
                Elf64SymbolType::STT_FUNC,
                Elf64SymbolSectionIdx::Index(1),
            )
        });
        let error = resolve_inputs(&symbols, &[], &FileNames::default())
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("multiple definition of symbol: duplicate")
        );
    }

    #[test]
    fn provide_is_selected_before_layout_for_an_undefined_weak_reference() {
        let symbols = [symbol(
            0,
            "provided",
            Elf64SymbolBinding::STB_WEAK,
            Elf64SymbolType::STT_NOTYPE,
            Elf64SymbolSectionIdx::Undefined,
        )];
        let script =
            parser::parse("PROVIDE_HIDDEN(provided = 42); PROVIDE(unused = missing);").unwrap();
        let assignments = script
            .statements
            .iter()
            .map(|statement| {
                let Statement::Assignment(assignment) = statement else {
                    panic!()
                };
                assignment
            })
            .collect::<Vec<_>>();
        let table = resolve_inputs(&symbols, &assignments, &FileNames::default()).unwrap();
        assert!(table.should_assign(assignments[0]));
        assert_eq!(table.should_assign(assignments[1]), false);
        let id = table
            .input(FileId::InputObject { input_index: 0 }, 1)
            .unwrap();
        assert!(matches!(
            table.get(id).definition,
            Definition::Script { .. }
        ));
        assert_eq!(table.get(id).address.get(), None);
        table
            .assign_addresses(
                &[],
                &HashMap::new(),
                &HashMap::from([("provided".to_string(), 42)]),
            )
            .unwrap();
        assert_eq!(table.get(id).address.get(), Some(&42));
    }

    #[test]
    fn tls_type_is_available_before_address_assignment() {
        let symbols = [symbol(
            0,
            "tls",
            Elf64SymbolBinding::STB_GLOBAL,
            Elf64SymbolType::STT_TLS,
            Elf64SymbolSectionIdx::Index(1),
        )];
        let table = resolve_inputs(&symbols, &[], &FileNames::default()).unwrap();
        assert_eq!(
            table.named("tls").unwrap().ty,
            Some(Elf64SymbolType::STT_TLS)
        );
        assert_eq!(table.named("tls").unwrap().address.get(), None);
    }
}
