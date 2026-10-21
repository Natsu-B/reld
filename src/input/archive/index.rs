//! Build a symbol index without loading each archive member into the link.
//!
//! [`index_archive`] takes mapped archive bytes and returns [`ArchiveState`].
//! [`MemberInfo`] holds each member's bytes; [`ArchiveEntry`] maps a symbol to a
//! member. Flags stop search from pulling the same member twice.
//!
//! We keep the armap's order because GNU ld searches it in that order. If there
//! is no armap, we read member definitions in member and symbol order to build
//! one. Weak definitions can meet a strong reference; local symbols cannot.
//!
//! A thin archive member's bytes come from the file that
//! [`super::thin::map_members`] mapped for it. Its name is that file's path, which
//! is how GNU ld names it too; a regular member is named `lib.a(member.o)`.
//!
//! References: ELF gABI "Symbol Binding"; [GNU ar indexes](https://sourceware.org/binutils/docs/binutils/ar.html)
//! and GNU ld/BFD armap search.

use std::collections::HashMap;

use anyhow::{Context, Result, anyhow};
use elf::{Elf64SymbolBinding, Elf64SymbolInfo, Elf64SymbolSectionIdx, Elf64SymbolType};

use crate::input::{FileId, object};

use super::{reader::ArchiveReader, thin::MemberFile};

/// Keep armap order and track members already pulled into the link.
pub(crate) struct ArchiveState<'a> {
    pub(crate) file_name: String,
    /// Position in the command-line list, used in member file IDs.
    pub(crate) archive_index: usize,
    pub(crate) members: Vec<MemberInfo<'a>>,
    /// Search in this order, even when members use a different order in the file.
    pub(crate) entries: Vec<ArchiveEntry<'a>>,
    /// One flag per member; several armap names can point to the same member.
    pub(crate) extracted: Vec<bool>,
}

impl<'a> ArchiveState<'a> {
    /// Borrow a member's ELF bytes once search needs them.
    ///
    /// A thin member whose file did not open fails here, with GNU ld's message.
    pub(crate) fn member_bytes(&self, member_index: usize) -> Result<&'a [u8]> {
        let member = &self.members[member_index];
        member.bytes.map_err(|error| {
            anyhow!(
                "{}({}): error opening thin archive member: {}",
                self.file_name,
                member.name,
                error.root_cause()
            )
        })
    }
}

/// Borrow a member's ELF bytes without adding its object to the link.
pub(crate) struct MemberInfo<'a> {
    /// The name GNU ld prints: `lib.a(member.o)`, or a thin member's file path.
    pub(crate) name: String,
    /// A thin member's file may fail to open. GNU ld reports that only when
    /// search pulls the member, so keep the error until then.
    bytes: Result<&'a [u8], &'a anyhow::Error>,
}

/// An armap name and its index in `ArchiveState::members`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ArchiveEntry<'a> {
    pub(crate) symbol: &'a str,
    pub(crate) member_index: usize,
}

/// Use the armap if present; otherwise build one in member and symbol order.
///
/// Reject armap offsets that do not point to object member headers. With an
/// armap, leave ELF parsing until search needs the member. `thin_members` holds
/// the mapped files of a thin archive, in member order, and is empty otherwise.
pub(crate) fn index_archive<'a>(
    bytes: &'a [u8],
    file_name: String,
    archive_index: usize,
    thin_members: &'a [MemberFile],
) -> Result<ArchiveState<'a>> {
    let reader = ArchiveReader::new(bytes)
        .with_context(|| format!("failed to parse archive: {file_name}"))?;
    let long_names = reader.long_name_table()?;
    let armap = reader.symbol_table()?;
    let mut members = Vec::new();
    let mut member_offsets = HashMap::new();

    for (member_index, member) in reader.object_members().enumerate() {
        let member =
            member.with_context(|| format!("failed to read archive member in {file_name}"))?;
        member_offsets.insert(member.header_offset(), member_index);
        let info = if reader.is_thin() {
            let file = thin_members
                .get(member_index)
                .with_context(|| format!("thin archive member file was not mapped: {file_name}"))?;
            MemberInfo {
                name: file.path.clone(),
                bytes: file.map.as_ref().map(|map| &map[..]),
            }
        } else {
            let name = member
                .resolved_name(long_names)
                .with_context(|| format!("failed to resolve archive member name in {file_name}"))?;
            let bytes = member
                .object_bytes()
                .with_context(|| format!("failed to read object bytes for {file_name}({name})"))?;
            MemberInfo {
                name: format!("{file_name}({name})"),
                bytes: Ok(bytes),
            }
        };
        members.push(info);
    }

    let mut state = ArchiveState {
        file_name,
        archive_index,
        extracted: vec![false; members.len()],
        members,
        entries: Vec::new(),
    };
    state.entries = match armap {
        Some(armap) => armap
            .into_iter()
            .map(|symbol| {
                let member_index =
                    *member_offsets.get(&symbol.member_offset).with_context(|| {
                        format!(
                            "archive symbol {} refers to invalid member offset {:#x}",
                            symbol.name, symbol.member_offset
                        )
                    })?;
                Ok(ArchiveEntry {
                    symbol: symbol.name,
                    member_index,
                })
            })
            .collect::<Result<_>>()?,
        // Without an armap, use the member and symbol order that an archiver
        // would use to build the index. This needs every member's bytes.
        None => {
            let mut entries = Vec::new();
            for member_index in 0..state.members.len() {
                let name = &state.members[member_index].name;
                let object = parse_member_object(
                    state.member_bytes(member_index)?,
                    name,
                    archive_index,
                    member_index,
                )
                .with_context(|| format!("failed to parse archive member {name}"))?;
                for symbol in collect_defined_symbols(&object) {
                    entries.push(ArchiveEntry {
                        symbol,
                        member_index,
                    });
                }
            }
            entries
        }
    };

    Ok(state)
}

fn parse_member_object<'a>(
    bytes: &'a [u8],
    member_name: &str,
    archive_index: usize,
    member_index: usize,
) -> Result<object::ObjectFile<'a>> {
    object::parse(
        bytes,
        member_name.to_string(),
        FileId::ArchiveMember {
            archive_index,
            member_index,
        },
    )
}

fn collect_defined_symbols<'a>(object: &object::ObjectFile<'a>) -> Vec<&'a str> {
    let mut defined = Vec::new();

    for symbol in &object.symbols {
        if symbol.name.is_empty() || symbol.section_idx == Elf64SymbolSectionIdx::Undefined {
            continue;
        }

        if matches!(
            symbol.info.get_enum(Elf64SymbolInfo::st_type),
            Some(Elf64SymbolType::STT_FILE | Elf64SymbolType::STT_SECTION)
        ) {
            continue;
        }

        if matches!(
            symbol.info.get_enum(Elf64SymbolInfo::st_bind),
            Some(Elf64SymbolBinding::STB_GLOBAL | Elf64SymbolBinding::STB_WEAK)
        ) {
            defined.push(symbol.name);
        }
    }

    defined
}

#[cfg(test)]
mod tests {
    //! Check that armap order and member offsets choose the right objects.

    use std::fs;

    use super::{ArchiveEntry, index_archive, parse_member_object};
    use crate::{
        input::{FileId, archive::thin::map_members},
        test_utils::{
            TestRelocation, TestSymbol, build_archive, build_rel_object, build_thin_archive,
        },
    };
    use elf::{Elf64SymbolBinding, Elf64SymbolType};
    use tempfile::TempDir;

    fn defines(name: &str) -> Vec<u8> {
        build_rel_object(
            &[TestSymbol {
                name,
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        )
    }

    /// Write objects under `obj/` and a thin archive at `lib/libthin.a` that
    /// names them as `../obj/<name>`. Leave out objects whose bytes are `None`.
    fn thin_fixture(
        objects: &[(&str, Option<&[u8]>)],
        entries: &[(&str, usize)],
    ) -> (TempDir, String) {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("lib")).unwrap();
        fs::create_dir(temp.path().join("obj")).unwrap();
        let mut members = Vec::new();
        for (name, bytes) in objects {
            if let Some(bytes) = bytes {
                fs::write(temp.path().join("obj").join(name), bytes).unwrap();
            }
            members.push((format!("../obj/{name}"), bytes.map_or(0, <[u8]>::len)));
        }
        let members = members
            .iter()
            .map(|(path, size)| (path.as_str(), *size))
            .collect::<Vec<_>>();
        let archive_path = format!("{}/lib/libthin.a", temp.path().display());
        fs::write(&archive_path, build_thin_archive(&members, entries)).unwrap();
        (temp, archive_path)
    }

    #[test]
    fn armap_entries_must_point_to_member_headers() {
        let object = build_rel_object(&[], &[]);
        let mut archive =
            crate::test_utils::build_indexed_archive(&[("member.o/", &object)], &[("symbol", 0)]);
        // An armap offset must find a member header, not bytes inside the index.
        archive[72..76].copy_from_slice(&8u32.to_be_bytes());
        let error = index_archive(&archive, "bad.a".to_string(), 0, &[])
            .err()
            .unwrap();
        assert!(error.to_string().contains("invalid member offset"));
    }

    #[test]
    fn indexes_single_member_archive() {
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
        let archive = build_archive(&[("foo.o/", &object)]);

        let state = index_archive(&archive, "libfoo.a".to_string(), 3, &[]).unwrap();

        assert_eq!(state.file_name, "libfoo.a");
        assert_eq!(state.archive_index, 3);
        assert_eq!(state.members.len(), 1);
        assert_eq!(state.members[0].name, "libfoo.a(foo.o)");
        assert_eq!(
            state.entries,
            vec![ArchiveEntry {
                symbol: "foo",
                member_index: 0
            }]
        );
        assert_eq!(state.extracted, vec![false]);
    }

    #[test]
    fn indexes_member_that_defines_multiple_symbols() {
        let object = build_rel_object(
            &[
                TestSymbol {
                    name: "foo",
                    binding: Elf64SymbolBinding::STB_GLOBAL,
                    ty: Elf64SymbolType::STT_FUNC,
                    section_idx: 2,
                    value: 0,
                    size: 5,
                },
                TestSymbol {
                    name: "bar",
                    binding: Elf64SymbolBinding::STB_WEAK,
                    ty: Elf64SymbolType::STT_FUNC,
                    section_idx: 2,
                    value: 1,
                    size: 4,
                },
            ],
            &[],
        );
        let archive = build_archive(&[("multi.o/", &object)]);

        let state = index_archive(&archive, "libmulti.a".to_string(), 1, &[]).unwrap();

        assert_eq!(
            state.entries,
            vec![
                ArchiveEntry {
                    symbol: "foo",
                    member_index: 0
                },
                ArchiveEntry {
                    symbol: "bar",
                    member_index: 0
                },
            ]
        );
    }

    #[test]
    fn duplicate_defined_symbols_keep_both_entries_in_member_order() {
        let first = build_rel_object(
            &[TestSymbol {
                name: "dup",
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        );
        let second = build_rel_object(
            &[TestSymbol {
                name: "dup",
                binding: Elf64SymbolBinding::STB_WEAK,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        );
        let archive = build_archive(&[("one.o/", &first), ("two.o/", &second)]);

        let state = index_archive(&archive, "libdup.a".to_string(), 0, &[]).unwrap();

        assert_eq!(state.members.len(), 2);
        assert_eq!(
            state.entries,
            vec![
                ArchiveEntry {
                    symbol: "dup",
                    member_index: 0
                },
                ArchiveEntry {
                    symbol: "dup",
                    member_index: 1
                },
            ]
        );
    }

    #[test]
    fn index_excludes_undefined_local_file_and_section_symbols() {
        let object = build_rel_object(
            &[
                TestSymbol {
                    name: "",
                    binding: Elf64SymbolBinding::STB_LOCAL,
                    ty: Elf64SymbolType::STT_SECTION,
                    section_idx: 2,
                    value: 0,
                    size: 0,
                },
                TestSymbol {
                    name: "member.c",
                    binding: Elf64SymbolBinding::STB_LOCAL,
                    ty: Elf64SymbolType::STT_FILE,
                    section_idx: 0xFFF1,
                    value: 0,
                    size: 0,
                },
                TestSymbol {
                    name: "local_only",
                    binding: Elf64SymbolBinding::STB_LOCAL,
                    ty: Elf64SymbolType::STT_FUNC,
                    section_idx: 2,
                    value: 1,
                    size: 1,
                },
                TestSymbol {
                    name: "foo",
                    binding: Elf64SymbolBinding::STB_GLOBAL,
                    ty: Elf64SymbolType::STT_FUNC,
                    section_idx: 2,
                    value: 0,
                    size: 5,
                },
                TestSymbol {
                    name: "bar",
                    binding: Elf64SymbolBinding::STB_WEAK,
                    ty: Elf64SymbolType::STT_FUNC,
                    section_idx: 2,
                    value: 1,
                    size: 4,
                },
                TestSymbol {
                    name: "baz",
                    binding: Elf64SymbolBinding::STB_GLOBAL,
                    ty: Elf64SymbolType::STT_NOTYPE,
                    section_idx: 0,
                    value: 0,
                    size: 0,
                },
            ],
            &[],
        );
        let archive = build_archive(&[("multi.o/", &object)]);

        let state = index_archive(&archive, "libmulti.a".to_string(), 2, &[]).unwrap();

        assert_eq!(
            state
                .entries
                .iter()
                .map(|entry| (entry.symbol, entry.member_index))
                .collect::<Vec<_>>(),
            vec![("foo", 0), ("bar", 0)]
        );
    }

    #[test]
    fn entries_map_each_symbol_to_the_correct_member() {
        let first = build_rel_object(
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
        let second = build_rel_object(
            &[TestSymbol {
                name: "bar",
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        );
        let archive = build_archive(&[("one.o/", &first), ("two.o/", &second)]);

        let state = index_archive(&archive, "libpair.a".to_string(), 4, &[]).unwrap();

        assert_eq!(
            state.entries,
            vec![
                ArchiveEntry {
                    symbol: "foo",
                    member_index: 0
                },
                ArchiveEntry {
                    symbol: "bar",
                    member_index: 1
                },
            ]
        );
    }

    #[test]
    fn archive_member_indexing_uses_archive_member_file_id() {
        let object = build_rel_object(
            &[
                TestSymbol {
                    name: "",
                    binding: Elf64SymbolBinding::STB_LOCAL,
                    ty: Elf64SymbolType::STT_SECTION,
                    section_idx: 2,
                    value: 0,
                    size: 0,
                },
                TestSymbol {
                    name: "foo",
                    binding: Elf64SymbolBinding::STB_GLOBAL,
                    ty: Elf64SymbolType::STT_FUNC,
                    section_idx: 2,
                    value: 0,
                    size: 5,
                },
            ],
            &[TestRelocation {
                offset: 0,
                sym: 2,
                ty: 2,
                addend: -4,
            }],
        );
        let archive = build_archive(&[("foo.o/", &object)]);
        let state = index_archive(&archive, "libfoo.a".to_string(), 9, &[]).unwrap();
        let file_id = FileId::ArchiveMember {
            archive_index: 9,
            member_index: 0,
        };

        let parsed =
            parse_member_object(state.member_bytes(0).unwrap(), &state.members[0].name, 9, 0)
                .unwrap();

        assert_eq!(parsed.file_id, file_id);
        assert!(
            parsed
                .sections
                .iter()
                .all(|section| section.file_id == file_id)
        );
        assert!(
            parsed
                .symbols
                .iter()
                .all(|symbol| symbol.file_id == file_id)
        );
        assert!(
            parsed
                .relocations
                .iter()
                .all(|relocation| relocation.file_id == file_id)
        );
    }

    #[test]
    fn thin_members_borrow_their_mapped_files() {
        let first = defines("first");
        let second = defines("second");
        let (_temp, path) = thin_fixture(
            &[("a.o", Some(&first)), ("b.o", Some(&second))],
            &[("second", 1), ("first", 0)],
        );
        let bytes = fs::read(&path).unwrap();
        let files = map_members(&bytes, &path).unwrap();

        let state = index_archive(&bytes, path.clone(), 0, &files).unwrap();

        let lib_dir = path.strip_suffix("libthin.a").unwrap();
        assert_eq!(state.members[0].name, format!("{lib_dir}../obj/a.o"));
        assert_eq!(state.member_bytes(1).unwrap(), second);
        assert_eq!(
            state.entries,
            [
                ArchiveEntry {
                    symbol: "second",
                    member_index: 1
                },
                ArchiveEntry {
                    symbol: "first",
                    member_index: 0
                },
            ]
        );
    }

    #[test]
    fn thin_archive_without_armap_reads_each_member_file() {
        let first = defines("first");
        let second = defines("second");
        let (_temp, path) = thin_fixture(&[("a.o", Some(&first)), ("b.o", Some(&second))], &[]);
        let bytes = fs::read(&path).unwrap();
        let files = map_members(&bytes, &path).unwrap();

        let state = index_archive(&bytes, path, 0, &files).unwrap();

        assert_eq!(
            state
                .entries
                .iter()
                .map(|entry| (entry.symbol, entry.member_index))
                .collect::<Vec<_>>(),
            [("first", 0), ("second", 1)]
        );
    }

    #[test]
    fn missing_thin_member_fails_only_when_its_bytes_are_needed() {
        let present = defines("present");
        let objects = [("a.o", Some(present.as_slice())), ("gone.o", None)];
        let (_temp, path) = thin_fixture(&objects, &[("present", 0), ("missing", 1)]);
        let bytes = fs::read(&path).unwrap();
        let files = map_members(&bytes, &path).unwrap();

        let state = index_archive(&bytes, path.clone(), 0, &files).unwrap();

        assert_eq!(state.member_bytes(0).unwrap(), present);
        let lib_dir = path.strip_suffix("libthin.a").unwrap();
        assert_eq!(
            state.member_bytes(1).unwrap_err().to_string(),
            format!(
                "{path}({lib_dir}../obj/gone.o): error opening thin archive member: \
                 No such file or directory (os error 2)"
            )
        );

        // Without an armap, indexing itself needs every member's bytes.
        let (_temp, path) = thin_fixture(&objects, &[]);
        let bytes = fs::read(&path).unwrap();
        let files = map_members(&bytes, &path).unwrap();
        let error = index_archive(&bytes, path, 0, &files).err().unwrap();
        assert!(
            error
                .to_string()
                .contains("error opening thin archive member")
        );
    }
}
