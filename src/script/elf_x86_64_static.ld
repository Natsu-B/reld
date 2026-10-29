/* Adapted from the GNU ld default linker script for elf_x86_64 (static link).
   Copyright (C) 2014-2026 Free Software Foundation, Inc.
   Copying and distribution of this script, with or without modification,
   are permitted in any medium without royalty provided the copyright
   notice and this notice are preserved.  */
ENTRY(_start)
SECTIONS
{
  PROVIDE_HIDDEN(__ehdr_start = SEGMENT_START("text-segment", 0x400000));
  . = SEGMENT_START("text-segment", 0x400000) + SIZEOF_HEADERS;
  .rela.plt : {
    PROVIDE_HIDDEN(__rela_iplt_start = .);
    *(.rela.iplt)
    PROVIDE_HIDDEN(__rela_iplt_end = .);
  }
  . = ALIGN(CONSTANT(MAXPAGESIZE));
  .init : { KEEP(*(SORT_NONE(.init))) }
  .plt : { *(.plt) *(.iplt) }
  .text : {
    *(.text.unlikely .text.*_unlikely .text.unlikely.*)
    *(.text.exit .text.exit.*)
    *(.text.startup .text.startup.*)
    *(.text.hot .text.hot.*)
    *(.text .stub .text.*)
  }
  .fini : { KEEP(*(SORT_NONE(.fini))) }
  PROVIDE(etext = .);
  . = ALIGN(CONSTANT(MAXPAGESIZE));
  .rodata : { *(.rodata .rodata.*) }
  .eh_frame : { KEEP(*(.eh_frame)) *(.eh_frame.*) }
  .gcc_except_table : { *(.gcc_except_table .gcc_except_table.*) }
  /* GNU property notes require per-property merging; concatenation would
     misrepresent the executable's features. Discard them until merging exists. */
  /DISCARD/ : { *(.note.gnu.property) }
  .note.ABI-tag : { *(.note.ABI-tag) }
  . = DATA_SEGMENT_ALIGN(CONSTANT(MAXPAGESIZE), CONSTANT(COMMONPAGESIZE));
  .tdata : { *(.tdata .tdata.*) }
  .tbss : { *(.tbss .tbss.*) *(.tcommon) }
  .preinit_array : {
    PROVIDE_HIDDEN(__preinit_array_start = .);
    KEEP(*(.preinit_array))
    PROVIDE_HIDDEN(__preinit_array_end = .);
  }
  .init_array : {
    PROVIDE_HIDDEN(__init_array_start = .);
    KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*)))
    KEEP(*(.init_array))
    PROVIDE_HIDDEN(__init_array_end = .);
  }
  .fini_array : {
    PROVIDE_HIDDEN(__fini_array_start = .);
    KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*)))
    KEEP(*(.fini_array))
    PROVIDE_HIDDEN(__fini_array_end = .);
  }
  .data.rel.ro : { *(.data.rel.ro.local*) *(.data.rel.ro .data.rel.ro.*) }
  .got : {
    PROVIDE_HIDDEN(_GLOBAL_OFFSET_TABLE_ = .);
    *(.got.plt) *(.igot.plt) *(.got) *(.igot)
  }
  .data : { *(.data .data.*) *(.tm_clone_table) }
  _edata = .;
  PROVIDE(edata = .);
  __bss_start = .;
  .bss : { *(.bss .bss.*) *(COMMON) }
  . = ALIGN(8);
  _end = .;
  PROVIDE(end = .);
}
