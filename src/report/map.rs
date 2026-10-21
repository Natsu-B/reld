//! Show why archive members entered the link and where their bytes went.
//!
//! [`render`] takes a [`LinkedImage`] and [`Reporter`] and returns map text.
//! The archive list uses GNU ld's member, requesting file, and symbol format.
//! The body lists output sections and their input parts, then symbols sorted by
//! address and name. TLS values here are template addresses, as used inside
//! the linker; the ELF symbol table instead holds TLS offsets.
//!
//! References: [GNU ld map output](https://sourceware.org/binutils/docs/ld/Options.html);
//! ELF gABI "Sections" and "Symbol Value".

use std::fmt::Write;

use elf::Elf64SymbolType;

use super::Reporter;
use crate::layout::LinkedImage;

pub(super) fn render(image: &LinkedImage, report: &Reporter) -> String {
    let mut text = archive_preamble(report);
    text.push_str("Linker script and memory map\n\n");
    for output in &image.layout.sections {
        let address = *output.address.get().unwrap();
        writeln!(text, "{} {address:#018x} {:#x}", output.name, output.size).unwrap();
        for (input, offset) in &output.inputs {
            writeln!(
                text,
                " {} {:#018x} {:#x} {}",
                input.name,
                address + offset,
                input.size,
                report.file_name(input.file_id),
            )
            .unwrap();
        }
    }
    text.push_str("\nSymbol addresses\n\n");
    let mut symbols = image
        .symbols
        .all_symbols()
        .filter(|symbol| {
            !symbol.name.is_empty()
                && symbol.address.get().is_some()
                && !matches!(
                    symbol.ty,
                    Some(Elf64SymbolType::STT_FILE | Elf64SymbolType::STT_SECTION)
                )
        })
        .collect::<Vec<_>>();
    symbols.sort_by_key(|symbol| (*symbol.address.get().unwrap(), &symbol.name));
    for symbol in symbols {
        writeln!(
            text,
            " {:#018x} {}",
            symbol.address.get().unwrap(),
            symbol.name
        )
        .unwrap();
    }
    text
}

fn archive_preamble(report: &Reporter) -> String {
    let mut text =
        String::from("Archive member included to satisfy reference by file (symbol)\n\n");
    for extraction in &report.extractions {
        write!(text, "{}", extraction.member).unwrap();
        // Match GNU ld: the requesting file starts in column 30. Once a member
        // name reaches 29 bytes, GNU ld moves the file to the next line, so at
        // least two spaces always follow a name that shares its line.
        if extraction.member.len() >= 29 {
            text.push('\n');
            text.push_str(&" ".repeat(30));
        } else {
            text.push_str(&" ".repeat(30 - extraction.member.len()));
        }
        if let Some(id) = extraction.referencer {
            write!(text, "{} ", report.file_name(id)).unwrap();
        }
        writeln!(text, "({})", extraction.symbol).unwrap();
    }
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    //! Check GNU ld's column rule for the archive list.

    use super::*;
    use crate::{input::FileId, report::Options, symbols::ArchiveExtraction};

    #[test]
    fn member_names_of_29_bytes_push_the_file_to_the_next_line() {
        let mut report = Reporter::new(Options {
            trace: Vec::new(),
            trace_symbol: Vec::new(),
            map: None,
        });
        let main = FileId::InputObject { input_index: 0 };
        report.files.insert(main, "main.o".to_string());
        for member in ["a".repeat(28), "b".repeat(29)] {
            report.extractions.push(ArchiveExtraction {
                member,
                symbol: "f".to_string(),
                referencer: Some(main),
            });
        }

        assert_eq!(
            archive_preamble(&report),
            format!(
                "Archive member included to satisfy reference by file (symbol)\n\n\
                 {}  main.o (f)\n{}\n{}main.o (f)\n\n",
                "a".repeat(28),
                "b".repeat(29),
                " ".repeat(30)
            )
        );
    }
}
