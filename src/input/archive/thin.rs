//! Find and map the object files that a thin archive points to.
//!
//! [`map_members`] takes the bytes and path of one input. For a thin archive it
//! returns a [`MemberFile`] for each object member, in member order; for any
//! other input it returns nothing. [`super::index::index_archive`] then borrows
//! these maps the same way it borrows a regular member's bytes.
//!
//! A thin archive stores each member as a path relative to the archive's own
//! directory. Like BFD, we put the archive path's directory in front of the
//! stored name and leave `..` alone, so `lib/libx.a` and `../obj/a.o` give
//! `lib/../obj/a.o`. GNU ld prints that same path in its link map.
//!
//! GNU ld opens a member file only when archive search pulls the member, so a
//! missing file that no one needs is not an error. We map every member here,
//! while inputs load, and keep any open error until search needs the member.
//!
//! References: [GNU ar thin archives](https://sourceware.org/binutils/docs/binutils/ar-cmdline.html)
//! (the `T` modifier); BFD `_bfd_append_relative_path` and `_bfd_get_elt_at_filepos`.

use anyhow::{Context, Result};
use memmap2::Mmap;
use rayon::prelude::*;

use super::reader::{ArchiveReader, is_thin_archive};
use crate::input::open::open_file_and_mmap;

/// The file one thin archive member points to.
pub(crate) struct MemberFile {
    /// The archive's directory joined to the stored name, as GNU ld prints it.
    pub(crate) path: String,
    /// Keep an open error: it matters only if search pulls this member.
    pub(crate) map: Result<Mmap>,
}

/// Map each object member of a thin archive; return nothing for other inputs.
///
/// Open the member files in parallel. A bad archive header is an error now; a
/// member file that fails to open is not.
pub(crate) fn map_members(bytes: &[u8], archive_path: &str) -> Result<Vec<MemberFile>> {
    if !is_thin_archive(bytes) {
        return Ok(Vec::new());
    }
    let reader = ArchiveReader::new(bytes)?;
    let long_names = reader.long_name_table()?;
    let paths = reader
        .object_members()
        .map(|member| {
            let name = member?.resolved_name(long_names)?;
            Ok(member_path(archive_path, &name))
        })
        .collect::<Result<Vec<_>>>()
        .with_context(|| format!("failed to read thin archive: {archive_path}"))?;
    Ok(paths
        .into_par_iter()
        .map(|path| {
            let map = open_file_and_mmap(&path);
            MemberFile { path, map }
        })
        .collect())
}

/// Join a stored member name to the archive's directory the way BFD does.
///
/// Keep an absolute name as it is. Otherwise copy the archive path up to and
/// including its last `/`. A bare `libx.a` has no directory, so the name stays
/// relative to the current directory.
pub(crate) fn member_path(archive_path: &str, name: &str) -> String {
    if name.starts_with('/') {
        return name.to_string();
    }
    match archive_path.rfind('/') {
        Some(end) => format!("{}{name}", &archive_path[..=end]),
        None => name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    //! Check BFD's path joins and that a missing member file waits for search.

    use super::*;
    use crate::test_utils::build_thin_archive;

    #[test]
    fn member_paths_follow_bfd_joins() {
        assert_eq!(member_path("lib/libx.a", "../obj/a.o"), "lib/../obj/a.o");
        assert_eq!(member_path("libx.a", "../obj/a.o"), "../obj/a.o");
        assert_eq!(member_path("/lib/libx.a", "a.o"), "/lib/a.o");
        assert_eq!(member_path("lib/libx.a", "/abs/a.o"), "/abs/a.o");
    }

    #[test]
    fn regular_inputs_have_no_member_files() {
        let archive = crate::test_utils::build_archive(&[("foo.o/", b"x")]);
        assert!(map_members(&archive, "libx.a").unwrap().is_empty());
        assert!(map_members(b"\x7FELF", "a.o").unwrap().is_empty());
    }

    #[test]
    fn missing_member_files_are_kept_as_errors() {
        let temp = tempfile::tempdir().unwrap();
        // The kernel walks `lib/..`, so `lib` must exist too.
        std::fs::create_dir(temp.path().join("lib")).unwrap();
        std::fs::create_dir(temp.path().join("obj")).unwrap();
        std::fs::write(temp.path().join("obj/a.o"), b"object").unwrap();
        let archive = build_thin_archive(&[("../obj/a.o", 6), ("../obj/gone.o", 4)], &[]);
        let archive_path = format!("{}/lib/libx.a", temp.path().display());

        let files = map_members(&archive, &archive_path).unwrap();

        let dir = temp.path().display();
        assert_eq!(files[0].path, format!("{dir}/lib/../obj/a.o"));
        assert_eq!(&files[0].map.as_ref().unwrap()[..], b"object");
        assert_eq!(files[1].path, format!("{dir}/lib/../obj/gone.o"));
        assert!(files[1].map.is_err());
    }
}
