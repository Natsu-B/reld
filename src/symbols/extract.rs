//! Pull archive members that define needed symbols.
//!
//! [`extract_archive_members`] takes [`LoadedInputs`], group ranges, and the
//! entry name. It returns [`ExtractedObjects`] and [`ArchiveExtraction`] reasons.
//! A strong undefined reference requires a definition. A weak reference is
//! optional, so it does not pull a member. ENTRY supplies the first required name.
//!
//! Like GNU ld/BFD, we visit each archive at its input position and scan the
//! armap from start to end. A member can add new references. Later armap entries
//! can meet them in that pass; earlier entries wait for the next pass. We stop
//! after a pass pulls nothing. Outside a group, search never returns to that
//! archive, so it cannot meet a reference from a later input.
//!
//! Static glibc has a cycle: libc.a needs helpers from libgcc.a, and those
//! helpers need libc.a again. A group repeats searches in command-line order
//! until a full pass pulls nothing. Objects enter only at their first position.
//! `gcc -static` passes `--start-group -lgcc -lgcc_eh -lc --end-group`.
//!
//! References: ELF gABI "Symbol Binding";
//! [GNU ld archive search and `--start-group`](https://sourceware.org/binutils/docs/ld/Options.html).

use std::{
    collections::{HashMap, HashSet},
    ops::Range,
};

use anyhow::{Context, Result};

use crate::input::{
    FileId, InputFile, LoadedInputs,
    archive::index::ArchiveState,
    object::{self, ObjectFile},
};

/// Objects in link order and the reasons for pulling archive members.
pub(crate) struct ExtractedObjects<'a> {
    pub(crate) files: Vec<ObjectFile<'a>>,
    pub(crate) extractions: Vec<ArchiveExtraction>,
}

/// Explain which missing symbol caused one archive member to enter the link.
#[derive(Clone)]
pub(crate) struct ArchiveExtraction {
    pub(crate) member: String,
    pub(crate) symbol: String,
    /// First object that needed this symbol, or `None` for ENTRY.
    pub(crate) referencer: Option<FileId>,
}

/// Scan each archive in full armap passes until a pass pulls no members.
///
/// Strong undefined names, including ENTRY, pull members. Weak names do not.
/// Groups repeat archive searches; other archives are searched only at their position.
pub(crate) fn extract_archive_members<'a>(
    inputs: LoadedInputs<'a>,
    entry_name: &str,
    groups: &[Range<usize>],
) -> Result<ExtractedObjects<'a>> {
    let mut objects = ExtractedObjects {
        files: Vec::new(),
        extractions: Vec::new(),
    };
    let mut defined = HashSet::new();
    // ENTRY must find a definition even before an input refers to it.
    let mut unresolved = HashMap::from([(entry_name.to_string(), None)]);
    let mut groups = groups.iter().filter(|group| !group.is_empty()).peekable();
    let mut archives = Vec::new();
    for (index, input) in inputs.files.into_iter().enumerate() {
        match input {
            InputFile::Object(object) => {
                update_symbol_sets(&object, &mut defined, &mut unresolved);
                objects.files.push(object);
            }
            InputFile::Archive(mut archive) => {
                search_archive(&mut archive, &mut objects, &mut defined, &mut unresolved)?;
                if groups.peek().is_some_and(|group| group.contains(&index)) {
                    archives.push(archive);
                }
            }
        }
        if groups.peek().is_some_and(|group| group.end == index + 1) {
            // GNU ld repeats while its undefined list grows. If pulled members
            // add no new strong undefined name, the next pass can pull nothing.
            // Counting pulled members gives the same result with one extra empty pass.
            loop {
                let mut loaded = false;
                for archive in &mut archives {
                    loaded |= search_archive(archive, &mut objects, &mut defined, &mut unresolved)?;
                }
                if !loaded {
                    break;
                }
            }
            archives.clear();
            groups.next();
        }
    }
    Ok(objects)
}

/// Repeat armap passes over one archive; return whether any member entered the link.
fn search_archive<'a>(
    archive: &mut ArchiveState<'a>,
    objects: &mut ExtractedObjects<'a>,
    defined: &mut HashSet<String>,
    unresolved: &mut HashMap<String, Option<FileId>>,
) -> Result<bool> {
    let mut pulled = false;
    // BFD finishes each armap pass before restarting. New names can pull
    // later entries here; earlier entries wait a pass.
    loop {
        let mut loaded = false;
        for entry in &archive.entries {
            let member_index = entry.member_index;
            if archive.extracted[member_index] || !unresolved.contains_key(entry.symbol) {
                continue;
            }
            let name = archive.members[member_index].name.clone();
            let file_id = FileId::ArchiveMember {
                archive_index: archive.archive_index,
                member_index,
            };
            let object = object::parse(archive.member_bytes(member_index)?, name.clone(), file_id)
                .with_context(|| format!("failed to parse archive member {name}"))?;
            objects.extractions.push(ArchiveExtraction {
                member: name,
                symbol: entry.symbol.to_string(),
                referencer: unresolved[entry.symbol],
            });
            archive.extracted[member_index] = true;
            update_symbol_sets(&object, defined, unresolved);
            objects.files.push(object);
            loaded = true;
            pulled = true;
        }
        if !loaded {
            return Ok(pulled);
        }
    }
}

fn update_symbol_sets(
    object: &ObjectFile<'_>,
    defined: &mut HashSet<String>,
    unresolved: &mut HashMap<String, Option<FileId>>,
) {
    for symbol in &object.symbols {
        if symbol.name.is_empty() {
            continue;
        }

        if matches!(
            symbol.info.get_enum(elf::Elf64SymbolInfo::st_type),
            Some(elf::Elf64SymbolType::STT_FILE | elf::Elf64SymbolType::STT_SECTION)
        ) {
            continue;
        }

        match symbol.section_idx {
            elf::Elf64SymbolSectionIdx::Undefined => {
                // A weak reference is optional and may stay zero. Only a
                // strong reference can require an archive member's bytes.
                if symbol.info.get_enum(elf::Elf64SymbolInfo::st_bind)
                    == Some(elf::Elf64SymbolBinding::STB_GLOBAL)
                    && !defined.contains(symbol.name)
                {
                    unresolved
                        .entry(symbol.name.to_string())
                        .or_insert(Some(object.file_id));
                }
            }
            _ => {
                if matches!(
                    symbol.info.get_enum(elf::Elf64SymbolInfo::st_bind),
                    Some(elf::Elf64SymbolBinding::STB_GLOBAL | elf::Elf64SymbolBinding::STB_WEAK)
                ) {
                    defined.insert(symbol.name.to_string());
                    unresolved.remove(symbol.name);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Check archive and group pass order, object positions, and strong references.

    use super::*;
    use crate::test_utils::{TestSymbol, build_rel_object};
    use elf::{Elf64SymbolBinding, Elf64SymbolType};

    fn symbol(
        name: &'static str,
        binding: Elf64SymbolBinding,
        section_idx: u16,
    ) -> TestSymbol<'static> {
        TestSymbol {
            name,
            binding,
            section_idx,
            ty: Elf64SymbolType::STT_NOTYPE,
            value: 0,
            size: 0,
        }
    }

    fn extract_names(root: &[u8], archive: &[u8]) -> Vec<String> {
        let root = object::parse(
            root,
            "root.o".to_string(),
            FileId::InputObject { input_index: 0 },
        )
        .unwrap();
        let archive =
            crate::input::archive::index::index_archive(archive, "libtest.a".to_string(), 1, &[])
                .unwrap();
        extract_archive_members(
            LoadedInputs {
                files: vec![InputFile::Object(root), InputFile::Archive(archive)],
            },
            "_start",
            &[],
        )
        .unwrap()
        .files
        .into_iter()
        .map(|object| object.file_name)
        .collect()
    }

    fn extract_inputs<'a>(
        inputs: &[(&str, &'a [u8])],
        groups: &[Range<usize>],
    ) -> ExtractedObjects<'a> {
        let files = inputs
            .iter()
            .enumerate()
            .map(|(input_index, &(name, bytes))| {
                if name.ends_with(".a") {
                    InputFile::Archive(
                        crate::input::archive::index::index_archive(
                            bytes,
                            name.to_string(),
                            input_index,
                            &[],
                        )
                        .unwrap(),
                    )
                } else {
                    InputFile::Object(
                        object::parse(bytes, name.to_string(), FileId::InputObject { input_index })
                            .unwrap(),
                    )
                }
            })
            .collect();
        extract_archive_members(LoadedInputs { files }, "_start", groups).unwrap()
    }

    fn names<'a>(objects: &'a ExtractedObjects<'_>) -> Vec<&'a str> {
        objects
            .files
            .iter()
            .map(|object| object.file_name.as_str())
            .collect()
    }

    fn cycle_inputs() -> [Vec<u8>; 3] {
        use Elf64SymbolBinding::STB_GLOBAL as Global;
        let root = build_rel_object(&[symbol("_start", Global, 2), symbol("a", Global, 0)], &[]);
        let a = build_rel_object(&[symbol("a", Global, 2), symbol("b", Global, 0)], &[]);
        let a2 = build_rel_object(&[symbol("a2", Global, 2)], &[]);
        let b = build_rel_object(&[symbol("b", Global, 2), symbol("a2", Global, 0)], &[]);
        [
            root,
            crate::test_utils::build_indexed_archive(
                &[("a.o/", &a), ("a2.o/", &a2)],
                &[("a", 0), ("a2", 1)],
            ),
            crate::test_utils::build_indexed_archive(&[("b.o/", &b)], &[("b", 0)]),
        ]
    }

    #[test]
    fn a_group_resolves_a_cycle_between_two_archives() {
        let [root, a, b] = cycle_inputs();
        let inputs = [("root.o", root.as_slice()), ("liba.a", &a), ("libb.a", &b)];
        assert_eq!(
            names(&extract_inputs(&inputs, &[])),
            ["root.o", "liba.a(a.o)", "libb.a(b.o)"]
        );
        let objects = extract_inputs(&inputs, &[1..3]);
        assert_eq!(
            names(&objects),
            ["root.o", "liba.a(a.o)", "libb.a(b.o)", "liba.a(a2.o)"]
        );
        assert_eq!(
            objects
                .extractions
                .iter()
                .map(|record| record.symbol.as_str())
                .collect::<Vec<_>>(),
            ["a", "b", "a2"]
        );
        assert_eq!(
            objects.extractions[2].referencer,
            Some(FileId::ArchiveMember {
                archive_index: 2,
                member_index: 0
            })
        );
    }

    #[test]
    fn an_archive_before_a_group_is_not_revisited() {
        use Elf64SymbolBinding::STB_GLOBAL as Global;
        let [root, _, b] = cycle_inputs();
        let a = build_rel_object(&[symbol("a", Global, 2), symbol("b", Global, 0)], &[]);
        let a = crate::test_utils::build_indexed_archive(&[("a.o/", &a)], &[("a", 0)]);
        let a2 = build_rel_object(&[symbol("a2", Global, 2)], &[]);
        let outside = crate::test_utils::build_indexed_archive(&[("a2.o/", &a2)], &[("a2", 0)]);
        let objects = extract_inputs(
            &[
                ("root.o", &root),
                ("outside.a", &outside),
                ("liba.a", &a),
                ("libb.a", &b),
            ],
            &[2..4],
        );
        assert_eq!(names(&objects), ["root.o", "liba.a(a.o)", "libb.a(b.o)"]);
    }

    #[test]
    fn an_archive_after_a_group_is_searched_after_all_group_passes() {
        use Elf64SymbolBinding::STB_GLOBAL as Global;
        let [root, _, b] = cycle_inputs();
        let a = build_rel_object(&[symbol("a", Global, 2), symbol("b", Global, 0)], &[]);
        let a2 = build_rel_object(&[symbol("a2", Global, 2), symbol("tail", Global, 0)], &[]);
        let extra = build_rel_object(&[symbol("extra", Global, 2)], &[]);
        let a = crate::test_utils::build_indexed_archive(
            &[("a.o/", &a), ("a2.o/", &a2), ("extra.o/", &extra)],
            &[("a", 0), ("a2", 1), ("extra", 2)],
        );
        let tail = build_rel_object(
            &[symbol("tail", Global, 2), symbol("extra", Global, 0)],
            &[],
        );
        let outside =
            crate::test_utils::build_indexed_archive(&[("tail.o/", &tail)], &[("tail", 0)]);
        let objects = extract_inputs(
            &[
                ("root.o", &root),
                ("liba.a", &a),
                ("libb.a", &b),
                ("outside.a", &outside),
            ],
            &[1..3],
        );
        assert_eq!(
            names(&objects),
            [
                "root.o",
                "liba.a(a.o)",
                "libb.a(b.o)",
                "liba.a(a2.o)",
                "outside.a(tail.o)"
            ]
        );
    }

    #[test]
    fn an_object_inside_a_group_enters_once_at_its_position() {
        use Elf64SymbolBinding::STB_GLOBAL as Global;
        let [_, a, b] = cycle_inputs();
        let root = build_rel_object(&[symbol("_start", Global, 2)], &[]);
        let middle = build_rel_object(&[symbol("a", Global, 0)], &[]);
        let objects = extract_inputs(
            &[
                ("root.o", &root),
                ("liba.a", &a),
                ("middle.o", &middle),
                ("libb.a", &b),
            ],
            &[1..4],
        );
        assert_eq!(
            names(&objects),
            [
                "root.o",
                "middle.o",
                "liba.a(a.o)",
                "libb.a(b.o)",
                "liba.a(a2.o)"
            ]
        );
    }

    #[test]
    fn finishes_each_pass_before_restarting_for_new_references() {
        use Elf64SymbolBinding::STB_GLOBAL as Global;
        let root = build_rel_object(
            &[
                symbol("_start", Global, 2),
                symbol("root", Global, 0),
                symbol("late", Global, 0),
            ],
            &[],
        );
        let early = build_rel_object(&[symbol("early", Global, 2)], &[]);
        let middle = build_rel_object(
            &[symbol("root", Global, 2), symbol("early", Global, 0)],
            &[],
        );
        let late = build_rel_object(&[symbol("late", Global, 2)], &[]);
        // Make file order differ from armap order so the test can tell them apart.
        let members = [
            ("late.o/", late.as_slice()),
            ("early.o/", early.as_slice()),
            ("middle.o/", middle.as_slice()),
        ];
        let archive = crate::test_utils::build_indexed_archive(
            &members,
            &[("early", 1), ("root", 2), ("late", 0)],
        );
        assert_eq!(
            extract_names(&root, &archive),
            [
                "root.o",
                "libtest.a(middle.o)",
                "libtest.a(late.o)",
                "libtest.a(early.o)"
            ]
        );
    }

    #[test]
    fn fallback_index_uses_member_then_symbol_order_with_full_passes() {
        use Elf64SymbolBinding::STB_GLOBAL as Global;
        let root = build_rel_object(
            &[symbol("_start", Global, 2), symbol("root", Global, 0)],
            &[],
        );
        let early = build_rel_object(&[symbol("early", Global, 2)], &[]);
        let middle = build_rel_object(
            &[
                symbol("root", Global, 2),
                symbol("early", Global, 0),
                symbol("later", Global, 0),
            ],
            &[],
        );
        let later = build_rel_object(&[symbol("later", Global, 2)], &[]);
        let archive = crate::test_utils::build_archive(&[
            ("early.o/", &early),
            ("middle.o/", &middle),
            ("later.o/", &later),
        ]);
        assert_eq!(
            extract_names(&root, &archive),
            [
                "root.o",
                "libtest.a(middle.o)",
                "libtest.a(later.o)",
                "libtest.a(early.o)"
            ]
        );
    }

    #[test]
    fn weak_references_do_not_extract_but_strong_references_can_select_weak_definitions() {
        use Elf64SymbolBinding::{STB_GLOBAL as Global, STB_WEAK as Weak};
        let member = build_rel_object(
            &[symbol("optional", Weak, 2), symbol("alias", Global, 2)],
            &[],
        );
        let archive = crate::test_utils::build_indexed_archive(
            &[("optional.o/", &member)],
            &[("optional", 0), ("alias", 0)],
        );
        for binding in [Weak, Global] {
            let root = build_rel_object(
                &[
                    symbol("_start", Global, 2),
                    symbol("optional", binding, 0),
                    symbol("alias", Weak, 0),
                ],
                &[],
            );
            let names = extract_names(&root, &archive);
            if binding == Weak {
                assert_eq!(names, ["root.o"]);
            } else {
                // Several armap names may point to this same member.
                assert_eq!(names, ["root.o", "libtest.a(optional.o)"]);
            }
        }
    }

    #[test]
    fn already_defined_symbols_do_not_pull_another_member() {
        use Elf64SymbolBinding::STB_GLOBAL as Global;
        let root = build_rel_object(
            &[symbol("_start", Global, 2), symbol("existing", Global, 2)],
            &[],
        );
        let member = build_rel_object(&[symbol("existing", Global, 2)], &[]);
        let archive = crate::test_utils::build_indexed_archive(
            &[("duplicate.o/", &member)],
            &[("existing", 0)],
        );
        assert_eq!(extract_names(&root, &archive), ["root.o"]);
    }

    #[test]
    fn weak_references_do_not_add_or_remove_archive_extraction_roots() {
        let object = |binding| {
            build_rel_object(
                &[TestSymbol {
                    name: "optional",
                    binding,
                    ty: Elf64SymbolType::STT_NOTYPE,
                    section_idx: 0,
                    value: 0,
                    size: 0,
                }],
                &[],
            )
        };
        let weak = object(Elf64SymbolBinding::STB_WEAK);
        let strong = object(Elf64SymbolBinding::STB_GLOBAL);
        let weak = object::parse(
            &weak,
            "weak.o".to_string(),
            FileId::InputObject { input_index: 0 },
        )
        .unwrap();
        let strong = object::parse(
            &strong,
            "strong.o".to_string(),
            FileId::InputObject { input_index: 1 },
        )
        .unwrap();
        let mut defined = HashSet::new();
        let mut unresolved = HashMap::new();
        update_symbol_sets(&weak, &mut defined, &mut unresolved);
        assert_eq!(unresolved, HashMap::new());
        update_symbol_sets(&strong, &mut defined, &mut unresolved);
        update_symbol_sets(&weak, &mut defined, &mut unresolved);
        assert_eq!(
            unresolved,
            HashMap::from([("optional".to_string(), Some(strong.file_id))])
        );
    }
}
