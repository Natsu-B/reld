//! A static x86-64 ELF linker that can link glibc programs.
//!
//! This crate takes object files, archives, and a linker script. It writes an
//! executable with all needed code and data. ELF sections tell the linker how to
//! join inputs; ELF segments tell the kernel which bytes to map into memory.
//!
//! [`main()`] runs these steps in order. The chapter numbers match the book's
//! module map. We read the script first because its ENTRY command can pull an
//! object from an archive.
//!
//! 1. Read options with [`cli::parse`] and set up [`report::Reporter`]
//!    (chapter 1: the whole link).
//! 2. Read the script with [`script::parse_script`] (chapter 4: script rules).
//! 3. Map input files with [`input::load`] (chapter 2: input files).
//! 4. Pull needed archive members with [`symbols::extract_archive_members`]
//!    (chapter 3: archive search).
//! 5. Match input sections to script rules with [`script::map_sections`]
//!    (chapter 4: section rules).
//! 6. Pick symbol definitions with [`symbols::resolve`]
//!    (chapter 5: symbol resolution).
//! 7. Build GOT and IFUNC section plans with [`synthetic::build`]
//!    (chapter 6: sections the linker makes).
//! 8. Set section and symbol addresses with [`layout::assign_addresses`]
//!    (chapter 7: layout).
//! 9. Patch symbol references with [`relocate::apply`]
//!    (chapter 8: relocation).
//! 10. Write the executable with [`output::write`] (chapter 9: output).
//!
//! [`layout::LinkedImage`] holds the bytes and addresses for the last three
//! steps. [`report`] shows each step's result and writes the link map.
//! [`debug`] supplies log macros. The [`elf`] crate reads and writes ELF records.
//!
//! References: [ELF gABI], "ELF Header", "Sections", "Symbol Table", "Relocation",
//! and "Program Loading"; [AMD64 psABI] §§4–5; [GNU ld] archive search and scripts.
//!
//! [ELF gABI]: https://gabi.xinuos.com/elf.pdf
//! [AMD64 psABI]: https://gitlab.com/x86-psABIs/x86-64-ABI
//! [GNU ld]: https://sourceware.org/binutils/docs/ld/

use std::{mem::MaybeUninit, ptr};

mod cli;
#[macro_use]
mod debug;
mod input;
mod layout;
mod output;
mod relocate;
mod report;
mod script;
mod symbols;
mod synthetic;
#[cfg(test)]
mod test_utils;

/// The main thread sets this before worker threads start; later access is read-only.
static mut DEBUG_LEVEL: MaybeUninit<u8> = MaybeUninit::new(0);

fn main() -> anyhow::Result<()> {
    let args = cli::parse();

    // SAFETY: Set this before worker threads start. All later access is
    // read-only, so log messages cannot race a write.
    unsafe {
        ptr::write((&raw mut DEBUG_LEVEL) as *mut u8, args.debug);
    }

    pr_debug!("Arguments: {:?}", args);

    let mut report = report::Reporter::new(args.report);

    // Read ENTRY before archive search so the entry name can pull a member.
    let script = script::parse_script(args.script.as_deref())?;
    // Names and section bytes borrow these maps until output finishes.
    let mut storage = input::MappedFiles::default();
    let files = input::load(&args.input, &mut storage)?;
    report.inputs(&files)?;
    let objects = symbols::extract_archive_members(files, script.entry_name())?;
    report.archive(&objects)?;
    // Mapping consumes the objects, but errors still need their file names.
    let names = input::FileNames::new(&objects.files);
    let mapping = script::map_sections(&script, objects)?;
    report.mapping(&mapping)?;
    let symbols = symbols::resolve(&mapping, &names)?;
    report.symbols(&symbols)?;
    let synthetic = synthetic::build(mapping, &symbols)?;
    report.synthetic(&synthetic, &symbols)?;
    let mut image = layout::assign_addresses(synthetic, symbols, script.entry_name())?;
    report.layout(&image)?;
    let relocations = relocate::apply(&mut image, report.relocation_symbols())?;
    report.relocations(&image, &relocations)?;
    report.write_map(&image)?;
    output::write(image, args.output)?;
    Ok(())
}
