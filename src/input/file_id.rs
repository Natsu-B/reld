//! Tell objects apart when their local names or ELF indices match.
//!
//! [`FileId`] names a command-line object, an archive member, or linker-made input.
//! ELF numbers sections and symbols within each object. A file ID plus that
//! number gives later steps a key that works even when two files both have a
//! local `loop` symbol or a section numbered one. [`FileNames`] maps each ID
//! back to the name the user gave, so errors can say which file to fix.
//!
//! References: ELF gABI "Sections" and "Symbol Table". GNU ld names archive
//! members as `lib.a(member.o)`; diagnostics keep both parts too.

use std::{collections::HashMap, fmt};

use super::object::ObjectFile;

/// An ELF index is unique only within its file, so lookups also need this ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FileId {
    /// `input_index` counts all command-line inputs, including archives.
    InputObject { input_index: usize },
    /// `member_index` counts object members, not the armap or name table.
    ArchiveMember {
        archive_index: usize,
        member_index: usize,
    },
    /// Use a separate file ID so linker-made indices cannot clash with input indices.
    LinkerGenerated,
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputObject { input_index } => write!(f, "input[{input_index}] (object)"),
            Self::LinkerGenerated => write!(f, "<linker>"),
            Self::ArchiveMember {
                archive_index,
                member_index,
            } => {
                write!(f, "input[{archive_index}] (archive member[{member_index}])")
            }
        }
    }
}

/// Name files the way the user typed them, such as `main.o` or `lib.a(put.o)`.
///
/// Errors should say which file to fix. A [`FileId`] alone only gives the
/// position on the command line, so keep the names after archive search.
#[derive(Default)]
pub(crate) struct FileNames(HashMap<FileId, String>);

impl FileNames {
    pub(crate) fn new(objects: &[ObjectFile]) -> Self {
        Self(
            objects
                .iter()
                .map(|object| (object.file_id, object.file_name.clone()))
                .collect(),
        )
    }

    /// Fall back to the [`FileId`] form for a file with no recorded name.
    pub(crate) fn show(&self, id: FileId) -> String {
        self.0.get(&id).cloned().unwrap_or_else(|| id.to_string())
    }
}
