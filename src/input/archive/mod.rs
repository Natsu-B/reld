//! Read an archive, then build the index used to pull its members.
//!
//! [`reader::ArchiveReader`] takes mapped ar bytes and finds members and symbols.
//! [`thin::map_members`] maps the object files a thin archive points to.
//! [`index::index_archive`] turns both into an [`index::ArchiveState`] for
//! [`crate::symbols::extract_archive_members`]. The archive is an ar file;
//! only its object members are ELF files.
//!
//! References: ELF gABI "Symbol Table"; [GNU ar](https://sourceware.org/binutils/docs/binutils/ar.html)
//! for names and symbol indexes. GNU ld uses that index's order to search members.

pub(crate) mod index;
pub(crate) mod reader;
pub(crate) mod thin;
