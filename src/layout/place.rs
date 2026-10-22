//! Place sections for one guess at the ELF header size.
//!
//! [`SectionPlacer::place`] takes mapped script rules and inputs and returns
//! [`OutputSection`] values. `PlacementState` keeps alignments and load flags.
//! We align each input, leave space between pages with different permissions,
//! and compute script symbols as the location counter `.` moves.
//!
//! We also remember which section each symbol belongs to. The address alone
//! cannot tell us: `data_end` and `__bss_start` may have the same value but belong
//! to different sections. A plain constant outside a section is absolute.
//! After a section ends, `.` still belongs to it for later script expressions.
//!
//! References: ELF gABI "Sections" and "Segment Permissions"; AMD64 psABI §5.1;
//! GNU ld's [location counter](https://sourceware.org/binutils/docs/ld/Location-Counter.html)
//! and output-section addresses.

use std::{cell::OnceCell, collections::HashMap};

use anyhow::{Context, Result, ensure};
use elf::{Elf64ProgramHeaderFlags, Elf64SymbolSectionIdx, PF_R};

use super::{OutputSection, PAGE_SIZE, ScriptSymbols};
use crate::{
    input::{FileId, object::InputSection},
    script::{
        ast::*,
        eval,
        mapping::{MappedItem, MappedOutputSection, MappedStatement, MappingInput},
    },
    symbols::{Definition, ResolvedSymbol, SymbolTable},
};

/// Run one placement pass, keeping symbol values and their sections together.
pub(super) struct SectionPlacer<'s> {
    context: eval::Context,
    symbols: &'s SymbolTable,
    section_symbols: HashMap<(FileId, u16), Vec<&'s ResolvedSymbol>>,
    script_symbols: HashMap<String, u64>,
    symbol_sections: HashMap<String, usize>,
    /// `.` still belongs to the last output section after that section's block ends.
    dot_section: Option<usize>,
    /// Page-aligned address of file offset zero, once the first output needs headers.
    pub(super) header_address: Option<u64>,
}

impl<'s> SectionPlacer<'s> {
    /// Start with a fixed header-size guess and the known absolute symbol values.
    pub(super) fn new(symbols: &'s SymbolTable, sizeof_headers: u64) -> Self {
        let mut section_symbols: HashMap<_, Vec<_>> = HashMap::new();
        let mut context = eval::Context {
            sizeof_headers,
            ..Default::default()
        };
        for symbol in symbols.named_symbols() {
            if let Definition::Input {
                file_id,
                section_idx,
                value,
            } = symbol.definition
            {
                match section_idx {
                    Elf64SymbolSectionIdx::Index(idx) => {
                        section_symbols
                            .entry((file_id, idx))
                            .or_default()
                            .push(symbol);
                    }
                    Elf64SymbolSectionIdx::AbsoluteSymbols => {
                        context.symbols.insert(symbol.name.clone(), value);
                    }
                    _ => {}
                }
            }
        }
        Self {
            context,
            symbols,
            section_symbols,
            script_symbols: HashMap::new(),
            symbol_sections: HashMap::new(),
            dot_section: None,
            header_address: None,
        }
    }

    /// Run mapped statements in order, aligning each input and filling output bytes.
    pub(super) fn place<'a>(
        &mut self,
        items: &[MappedItem],
        inputs: &[MappingInput<'a>],
    ) -> Result<Vec<OutputSection<'a>>> {
        let mut sections = Vec::new();
        let mut state = PlacementState::new(items);
        for (item_index, item) in items.iter().enumerate() {
            self.context.next_section_alignment =
                next_section_alignment(&items[item_index + 1..], inputs);
            match item {
                MappedItem::Assignment(assignment) => self.assign(assignment, None)?,
                MappedItem::Output(output) => {
                    if output.statements.is_empty() {
                        continue;
                    }
                    let section = self.place_output(output, inputs, sections.len(), &mut state)?;
                    sections.push(section);
                }
            }
        }
        Ok(sections)
    }

    /// Keep script names for output. Expressions can also use input names.
    pub(super) fn into_script_symbols(mut self) -> ScriptSymbols {
        self.symbol_sections
            .retain(|name, _| self.script_symbols.contains_key(name));
        ScriptSymbols {
            values: self.script_symbols,
            sections: self.symbol_sections,
        }
    }

    fn assign(&mut self, assignment: &Assignment, output_index: Option<usize>) -> Result<()> {
        if !self.symbols.should_assign(assignment) {
            return Ok(());
        }
        let value = eval::evaluate(&assignment.value, &self.context)?;
        if assignment.name == "." {
            self.context.dot = value;
        } else {
            // Equal addresses need not belong to the same section. Keep the
            // section too, so .symtab can tell end markers from absolute values.
            let section = output_index.or(self.expression_section(&assignment.value)?);
            if let Some(section) = section {
                self.symbol_sections
                    .insert(assignment.name.clone(), section);
            } else {
                self.symbol_sections.remove(&assignment.name);
            }
            self.context.symbols.insert(assignment.name.clone(), value);
            self.script_symbols.insert(assignment.name.clone(), value);
        }
        Ok(())
    }

    fn expression_section(&self, expr: &Expr) -> Result<Option<usize>> {
        Ok(match &expr.kind {
            ExprKind::Dot => self.dot_section,
            ExprKind::Symbol(name) => self.symbol_sections.get(name).copied(),
            ExprKind::Binary(op, left, right) => {
                let left = self.expression_section(left)?;
                let right = self.expression_section(right)?;
                match op {
                    BinaryOp::Add => left.or(right),
                    BinaryOp::Subtract if right.is_none() => left,
                    _ => None,
                }
            }
            ExprKind::Conditional(condition, yes, no) => {
                self.expression_section(if eval::evaluate(condition, &self.context)? != 0 {
                    yes
                } else {
                    no
                })?
            }
            ExprKind::Call(Function::Align, args) => {
                if args.len() == 1 {
                    self.dot_section
                } else {
                    self.expression_section(&args[0])?
                }
            }
            ExprKind::Call(Function::DataSegmentRelroEnd, args) => {
                self.expression_section(&args[1])?
            }
            ExprKind::Call(Function::DataSegmentEnd, args) => self.expression_section(&args[0])?,
            _ => None,
        })
    }

    fn place_output<'a>(
        &mut self,
        output: &MappedOutputSection,
        inputs: &[MappingInput<'a>],
        output_index: usize,
        state: &mut PlacementState,
    ) -> Result<OutputSection<'a>> {
        let output_align = state.output_alignment(output, inputs);
        let address = self.output_address(output, inputs, output_align, state)?;
        self.context.dot = address;
        self.dot_section = Some(output_index);
        let mut section = OutputSection {
            name: output.name.clone(),
            flags: output.permissions(),
            size: 0,
            align: output_align,
            address: OnceCell::from(address),
            data: None,
            inputs: Vec::new(),
        };
        for statement in &output.statements {
            match statement {
                MappedStatement::Assignment(assignment) => {
                    self.assign_in_section(assignment, &section.name, output_index)?
                }
                MappedStatement::Input(index) => {
                    self.place_input(&inputs[*index].section, &mut section, output_index)?
                }
            }
        }
        section.size = self.context.dot - address;
        state.finish_output(&section, self.context.dot)?;
        pr_debug!(
            "Output section {} at {address:#x}, size {:#x}",
            section.name,
            section.size
        );
        Ok(section)
    }

    fn assign_in_section(
        &mut self,
        assignment: &Assignment,
        name: &str,
        output_index: usize,
    ) -> Result<()> {
        let old_dot = self.context.dot;
        self.assign(assignment, Some(output_index))?;
        ensure!(
            self.context.dot >= old_dot,
            "location counter moves backwards in output section {name}"
        );
        Ok(())
    }

    fn output_address(
        &mut self,
        output: &MappedOutputSection,
        inputs: &[MappingInput],
        alignment: u64,
        state: &mut PlacementState,
    ) -> Result<u64> {
        let mut address = match output.address {
            Some(expression) => eval::evaluate(expression, &self.context)?,
            None => align(self.context.dot, alignment)?,
        };
        if self.header_address.is_none() {
            self.reserve_headers(address, state)?;
        }
        if output.has_contents(inputs) {
            let minimum = state.minimum_address(output.permissions())?;
            if output.address.is_some() {
                ensure!(
                    address >= minimum,
                    "output section {} at {address:#x} overlaps a previous section or shares a page with different permissions",
                    output.name
                );
            } else {
                address = align(address.max(minimum), alignment)?;
            }
        }
        Ok(address)
    }

    fn reserve_headers(&mut self, address: u64, state: &mut PlacementState) -> Result<()> {
        let first_address = if self.context.dot >= self.context.sizeof_headers {
            self.context.dot.min(address)
        } else {
            address
        };
        let base = first_address
            .checked_sub(self.context.sizeof_headers)
            .context("no space for mapped ELF headers before the first output section")?
            / PAGE_SIZE
            * PAGE_SIZE;
        self.header_address = Some(base);
        state.previous_end = base + self.context.sizeof_headers;
        Ok(())
    }

    fn place_input<'a>(
        &mut self,
        input: &InputSection<'a>,
        section: &mut OutputSection<'a>,
        output_index: usize,
    ) -> Result<()> {
        self.context.dot = align(self.context.dot, input.align.max(1))?;
        let offset = self.context.dot - section.address.get().unwrap();
        if let Some(data) = input.data.as_deref() {
            ensure!(
                data.len() as u64 == input.size,
                "input section {} data length does not match size",
                input.name
            );
            let output_data = section.data.get_or_insert_with(Vec::new);
            output_data.resize(
                usize::try_from(offset).context("output section too large")?,
                0,
            );
            output_data.extend_from_slice(data);
        }
        self.record_input_symbols(input, output_index)?;
        self.context.dot = self
            .context
            .dot
            .checked_add(input.size)
            .context("output section address exceeds u64")?;
        section.inputs.push((input.clone(), offset));
        Ok(())
    }

    fn record_input_symbols(&mut self, input: &InputSection, output_index: usize) -> Result<()> {
        for symbol in self
            .section_symbols
            .get(&(input.file_id, input.idx))
            .into_iter()
            .flatten()
        {
            let Definition::Input { value, .. } = symbol.definition else {
                unreachable!()
            };
            self.context.symbols.insert(
                symbol.name.clone(),
                self.context
                    .dot
                    .checked_add(value)
                    .context("symbol address exceeds u64")?,
            );
            self.symbol_sections
                .insert(symbol.name.clone(), output_index);
        }
        Ok(())
    }
}

/// Track page permissions and TLS alignment across output sections.
struct PlacementState {
    previous_flags: Elf64ProgramHeaderFlags,
    previous_end: u64,
    tls_align: u64,
    tls_started: bool,
}

impl PlacementState {
    fn new(items: &[MappedItem]) -> Self {
        let tls_align = items
            .iter()
            .filter_map(|item| match item {
                MappedItem::Output(output) if output.is_tls() => Some(output.align),
                _ => None,
            })
            .max()
            .unwrap_or(1);
        Self {
            previous_flags: Elf64ProgramHeaderFlags::from_bits(PF_R),
            previous_end: 0,
            tls_align,
            tls_started: false,
        }
    }

    fn output_alignment(&mut self, output: &MappedOutputSection, inputs: &[MappingInput]) -> u64 {
        if !self.tls_started && output.is_tls() && output.has_contents(inputs) {
            // PT_TLS starts here, so align it for the whole block. A later
            // .tbss input may need stricter alignment than .tdata does.
            self.tls_started = true;
            output.align.max(self.tls_align)
        } else {
            output.align
        }
    }

    fn minimum_address(&self, flags: Elf64ProgramHeaderFlags) -> Result<u64> {
        if flags == self.previous_flags {
            Ok(self.previous_end)
        } else {
            // The kernel sets permissions per page. Sections with different
            // flags must not share a page, even if their bytes would fit.
            align(self.previous_end, PAGE_SIZE)
        }
    }

    fn finish_output(&mut self, section: &OutputSection, end: u64) -> Result<()> {
        if section.size != 0 {
            let address = *section.address.get().unwrap();
            ensure!(
                address >= self.previous_end,
                "output section {} overlaps a previous section",
                section.name
            );
            ensure!(
                address >= self.minimum_address(section.flags)?,
                "output section {} shares a page with different permissions",
                section.name
            );
            self.previous_end = end;
            self.previous_flags = section.flags;
        }
        Ok(())
    }
}

fn next_section_alignment(items: &[MappedItem], inputs: &[MappingInput]) -> u64 {
    items
        .iter()
        .find_map(|item| match item {
            MappedItem::Output(output) if output.has_contents(inputs) => Some(output.align),
            _ => None,
        })
        .unwrap_or(1)
}

fn align(value: u64, alignment: u64) -> Result<u64> {
    value
        .checked_next_multiple_of(alignment)
        .context("aligned address exceeds u64")
}

#[cfg(test)]
mod tests {
    //! Check page gaps, TLS alignment, and which section each script symbol belongs to.

    use super::*;
    use crate::{
        input::{FileNames, object::InputSection},
        layout::{segments::load_segment_count, tls::TlsSegment},
        script::{
            mapping::{input_name, map_inputs},
            parser,
        },
    };
    use elf::Elf64SectionFlags;

    fn input(file: &str, name: &'static str, flags: u64, align: u64) -> MappingInput<'static> {
        MappingInput {
            file_name: input_name(
                file,
                if file.ends_with(')') {
                    FileId::ArchiveMember {
                        archive_index: 0,
                        member_index: 0,
                    }
                } else {
                    FileId::InputObject { input_index: 0 }
                },
            )
            .to_string(),
            section: InputSection {
                file_id: FileId::InputObject { input_index: 0 },
                idx: 1,
                name,
                flags: Elf64SectionFlags::from_bits(flags),
                section_type: elf::Elf64SectionType::SHT_PROGBITS,
                entry_size: 0,
                align,
                data: Some(std::borrow::Cow::Borrowed(&[1])),
                size: 1,
            },
        }
    }

    fn names<'a>(items: &'a [MappedItem<'_>]) -> Vec<&'a str> {
        items
            .iter()
            .filter_map(|item| match item {
                MappedItem::Output(output) => Some(output.name.as_str()),
                _ => None,
            })
            .collect()
    }

    fn members(output: &MappedOutputSection) -> Vec<usize> {
        output
            .statements
            .iter()
            .filter_map(|statement| match statement {
                MappedStatement::Input(index) => Some(*index),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn orphans_follow_the_last_output_with_the_same_flags() {
        let inputs = vec![
            input("a.o", ".text", 6, 16),
            input("a.o", ".rodata", 2, 8),
            input("a.o", ".data", 3, 8),
            input("a.o", ".extra", 6, 32),
            input("b.o", ".extra", 6, 16),
            input("a.o", ".other", 2, 8),
        ];
        let script = parser::parse("SECTIONS { . = 0x400000 + SIZEOF_HEADERS; .text : { *(.text) } .rodata : { *(.rodata) } .data : { *(.data) } }").unwrap();
        let items = map_inputs(&script, &inputs).unwrap();
        assert_eq!(
            names(&items),
            vec![".text", ".extra", ".rodata", ".other", ".data"]
        );
        let MappedItem::Output(extra) = &items[2] else {
            panic!()
        };
        assert_eq!(members(extra), vec![3, 4]);
        let symbols = SymbolTable::default();
        let mut placer = SectionPlacer::new(&symbols, 64 + 56 * 5);
        let sections = placer.place(&items, &inputs).unwrap();
        let text = &sections[0];
        let extra = &sections[1];
        let rodata = &sections[2];
        assert_eq!(*extra.address.get().unwrap() % 32, 0);
        assert_eq!(
            *extra.address.get().unwrap(),
            (*text.address.get().unwrap() + 1).next_multiple_of(32)
        );
        assert_eq!(*rodata.address.get().unwrap() % PAGE_SIZE, 0);
        assert_eq!(load_segment_count(&sections), 4);
    }

    #[test]
    fn info_discard_and_nonalloc_outputs_do_not_change_dot() {
        let inputs = vec![
            input("a.o", ".debug_info", 0, 1),
            input("a.o", ".ignored", 2, 1),
            input("a.o", ".drop", 2, 1),
            input("a.o", ".text", 6, 1),
        ];
        let script = parser::parse("SECTIONS { . = 0x401000; .debug_info 0 : { *(.debug_info) } .info 0 (INFO) : { *(.ignored) } /DISCARD/ : { *(.drop) } .text : { *(.text) } }").unwrap();
        let items = map_inputs(&script, &inputs).unwrap();
        assert_eq!(names(&items), vec![".text"]);
        let symbols = SymbolTable::default();
        let mut placer = SectionPlacer::new(&symbols, 232);
        let sections = placer.place(&items, &inputs).unwrap();
        assert_eq!(*sections[0].address.get().unwrap(), 0x401000);
    }

    #[test]
    fn rejects_explicit_sections_sharing_a_page_with_different_permissions() {
        let inputs = vec![input("a.o", ".text", 6, 1), input("a.o", ".data", 3, 1)];
        let script = parser::parse("SECTIONS { . = 0x400000 + SIZEOF_HEADERS; .text 0x401000 : { *(.text) } .data 0x401001 : { *(.data) } }").unwrap();
        let items = map_inputs(&script, &inputs).unwrap();
        let symbols = SymbolTable::default();
        let mut placer = SectionPlacer::new(&symbols, 232);
        let error = placer.place(&items, &inputs).err().unwrap();
        assert!(
            error
                .to_string()
                .contains("shares a page with different permissions")
        );
    }

    #[test]
    fn next_section_alignment_and_sequential_assignments() {
        let inputs = vec![
            input("a.o", ".rodata", 2, 64),
            input("a.o", ".data", 3, 128),
        ];
        let script = parser::parse("SECTIONS { . = 0x400000 + SIZEOF_HEADERS; before = .; alignment = ALIGNOF(NEXT_SECTION); .rodata : { start = .; next_alignment = ALIGNOF(NEXT_SECTION); *(.rodata) . = ALIGN(16); finish = .; } after = .; .data : { *(.data) } }").unwrap();
        let items = map_inputs(&script, &inputs).unwrap();
        let symbols = SymbolTable::default();
        let mut placer = SectionPlacer::new(&symbols, 176);
        let sections = placer.place(&items, &inputs).unwrap();
        assert_eq!(placer.script_symbols["before"], 0x4000b0);
        assert_eq!(placer.script_symbols["alignment"], 64);
        assert_eq!(placer.script_symbols["next_alignment"], 128);
        assert_eq!(placer.script_symbols["start"], 0x4000c0);
        assert_eq!(placer.script_symbols["finish"], 0x4000d0);
        assert_eq!(placer.script_symbols["after"], 0x4000d0);
        assert_eq!(sections[0].size, 16);
    }

    #[test]
    fn script_symbols_keep_sections_when_values_match() {
        use crate::input::object::ObjectSymbol;
        use elf::{Elf64SymbolBinding, Elf64SymbolInfo, Elf64SymbolType};

        let mut inputs = vec![input("a.o", ".data", 3, 1), input("a.o", ".bss", 3, 1)];
        inputs[1].section.idx = 2;
        inputs[1].section.data = None;
        let input_symbol = ObjectSymbol {
            file_id: inputs[0].section.file_id,
            idx: 1,
            section_idx: Elf64SymbolSectionIdx::Index(1),
            name: "input_data",
            info: Elf64SymbolInfo::new()
                .set(
                    Elf64SymbolInfo::st_bind,
                    Elf64SymbolBinding::STB_GLOBAL as u8,
                )
                .set(Elf64SymbolInfo::st_type, Elf64SymbolType::STT_OBJECT as u8),
            size: 1,
            other: 0,
            value: 0,
        };
        let symbols =
            crate::symbols::resolve_inputs(&[input_symbol], &[], &FileNames::default()).unwrap();
        let script = parser::parse(
            "SECTIONS {
                . = 0x401000;
                .data : { *(.data) inside = 7; data_end = .; }
                after = .;
                alias = input_data;
                absolute = 7;
                .bss : { bss_start = .; *(.bss) }
            }",
        )
        .unwrap();
        let items = map_inputs(&script, &inputs).unwrap();
        let mut placer = SectionPlacer::new(&symbols, 232);
        placer.place(&items, &inputs).unwrap();
        let script_symbols = placer.into_script_symbols();

        assert_eq!(
            script_symbols.values["data_end"],
            script_symbols.values["bss_start"]
        );
        assert_eq!(
            script_symbols.values["inside"],
            script_symbols.values["absolute"]
        );
        for name in ["data_end", "after", "alias", "inside"] {
            assert_eq!(script_symbols.sections[name], 0);
        }
        assert_eq!(script_symbols.sections["bss_start"], 1);
        assert!(!script_symbols.sections.contains_key("absolute"));
        assert!(!script_symbols.sections.contains_key("input_data"));
        assert!(!script_symbols.values.contains_key("input_data"));
    }

    #[test]
    fn tls_start_uses_maximum_alignment_and_tbss_reserves_address_space() {
        let mut inputs = vec![
            input("a.o", ".prefix", 3, 1),
            input("a.o", ".tdata", 0x403, 8),
            input("a.o", ".tbss", 0x403, 32),
            input("a.o", ".data", 3, 8),
        ];
        inputs[2].section.data = None;
        let script = parser::parse(
            "SECTIONS { . = 0x401000; .prefix : { *(.prefix) . = ALIGN(16); } .tdata : { *(.tdata) } .tbss : { *(.tbss) } .data : { *(.data) } }",
        ).unwrap();
        let items = map_inputs(&script, &inputs).unwrap();
        let symbols = SymbolTable::default();
        let mut placer = SectionPlacer::new(&symbols, 288);
        let sections = placer.place(&items, &inputs).unwrap();
        assert_eq!(*sections[1].address.get().unwrap(), 0x401020);
        assert_eq!(*sections[2].address.get().unwrap(), 0x401040);
        assert_eq!(*sections[3].address.get().unwrap(), 0x401048);
        assert_eq!(
            TlsSegment::from_sections(&sections).unwrap(),
            Some(TlsSegment {
                vaddr: 0x401020,
                file_size: 1,
                mem_size: 33,
                align: 32,
            })
        );
    }
}
