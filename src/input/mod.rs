//! Read object files and archives without copying their contents.
//!
//! [`load`] takes paths and returns [`LoadedInputs`] in command-line order.
//! Rayon opens and reads separate files in parallel. [`MappedFiles`] owns the
//! memory maps while names and section bytes borrow them. A thin archive names
//! other files for its members, so we map those here too; later stages never
//! open files.
//!
//! An ELF `ET_REL` file holds code whose addresses still need patches. An archive
//! holds such objects and a symbol index, called an armap. [`InputFile`] keeps
//! these cases separate so archive search can pull only the members it needs.
//! Like GNU ld, that search depends on the order of the input paths.
//!
//! References: ELF gABI "ELF Header", "Sections", and "Symbol Table"; AMD64 psABI
//! §4.1; [GNU ld archive search](https://sourceware.org/binutils/docs/ld/Options.html).

pub(crate) mod archive;
mod file_id;
pub(crate) mod object;
mod open;

use anyhow::{Result, ensure};
use memmap2::Mmap;
use rayon::prelude::*;

pub(crate) use file_id::{FileId, FileNames};

/// An object enters the link at once; an archive waits for a needed symbol.
pub(crate) enum InputFile<'a> {
    Object(object::ObjectFile<'a>),
    Archive(archive::index::ArchiveState<'a>),
}

/// Own the maps while parsed names and section bytes borrow from them.
#[derive(Default)]
pub(crate) struct MappedFiles {
    /// One map per command-line path, in the same order.
    inputs: Vec<Mmap>,
    /// For each input, the member files of a thin archive; empty for other inputs.
    thin_members: Vec<Vec<archive::thin::MemberFile>>,
}

/// Keep command-line order, which sets when archive search sees each reference.
pub(crate) struct LoadedInputs<'a> {
    pub(crate) files: Vec<InputFile<'a>>,
}

/// Map and parse files in parallel while keeping command-line order.
///
/// The returned names and bytes borrow `storage`, which must outlive the link.
/// Report every file error before returning a failed stage.
pub(crate) fn load<'a>(paths: &[String], storage: &'a mut MappedFiles) -> Result<LoadedInputs<'a>> {
    let opened = paths.par_iter().map(open::open_file_and_mmap).collect();
    storage.inputs = collect_results(opened, paths, "open")?;
    let members = storage
        .inputs
        .par_iter()
        .zip(paths.par_iter())
        .map(|(bytes, path)| archive::thin::map_members(bytes, path))
        .collect();
    storage.thin_members = collect_results(members, paths, "read")?;

    let storage = &*storage;
    let parsed = storage
        .inputs
        .par_iter()
        .zip(storage.thin_members.par_iter())
        .zip(paths.par_iter())
        .enumerate()
        .map(|(input_index, ((bytes, thin_members), path))| {
            if elf::Elf64::check_elf_magic(bytes) {
                object::parse(bytes, path.clone(), FileId::InputObject { input_index })
                    .map(InputFile::Object)
            } else {
                archive::index::index_archive(bytes, path.clone(), input_index, thin_members)
                    .map(InputFile::Archive)
            }
        })
        .collect();
    Ok(LoadedInputs {
        files: collect_results(parsed, paths, "parse")?,
    })
}

fn collect_results<T>(results: Vec<Result<T>>, paths: &[String], action: &str) -> Result<Vec<T>> {
    let mut values = Vec::with_capacity(results.len());
    let mut errors = 0;
    for (result, path) in results.into_iter().zip(paths) {
        match result {
            Ok(value) => values.push(value),
            Err(error) => {
                debugs_or!(
                    pr_err!("file:{path}: {error:?}"),
                    pr_err!("file:{path}: {error}")
                );
                errors += 1;
            }
        }
    }
    ensure!(errors == 0, "{errors} file(s) failed to {action}");
    Ok(values)
}
