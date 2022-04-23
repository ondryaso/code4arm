OUTPUT_FORMAT("elf32-littlearm", "elf32-bigarm", "elf32-littlearm")
OUTPUT_ARCH(arm)
ENTRY(_start)
SEARCH_DIR("=/arm-none-linux-gnueabihf/lib"); SEARCH_DIR("=/usr/local/lib"); SEARCH_DIR("=/lib"); SEARCH_DIR("=/usr/lib");

MEMORY
{
    mappedio   (!rwxai) : ORIGIN = 0xfe000000, LENGTH = 16777215
    trampoline (!rwxai) : ORIGIN = 0xff000000, LENGTH = 16777215
}

SECTIONS
{
    /* TEXT */
    PROVIDE (__executable_start = SEGMENT_START("text-segment", 0x00010000)); . = SEGMENT_START("text-segment", 0x00010000) + SIZEOF_HEADERS;
    .dynsym         : { *(.dynsym) }
    .dynstr         : { *(.dynstr) }
    .text           :
    {
        *(.text.unlikely .text.*_unlikely .text.unlikely.*)
        *(.text.exit .text.exit.*)
        *(.text.startup .text.startup.*)
        *(.text.hot .text.hot.*)
        *(SORT(.text.sorted.*))
        *(.text .stub .text.* .gnu.linkonce.t.*)
        /* .gnu.warning sections are handled specially by elf.em.  */
        *(.gnu.warning)
        *(.glue_7t) *(.glue_7) *(.vfp11_veneer) *(.v4_bx)
    }
    PROVIDE (__etext = .);
    PROVIDE (_etext = .);
    PROVIDE (etext = .);
    
    /* DATA */
    . = DATA_SEGMENT_ALIGN (CONSTANT (MAXPAGESIZE), CONSTANT (COMMONPAGESIZE));
    . = DATA_SEGMENT_RELRO_END (0, .);
    .data           :
    {
        PROVIDE (__data_start = .);
        *(.data .data.* .gnu.linkonce.d.*)
        SORT(CONSTRUCTORS)
    }
    .data1          : { *(.data1) }
    PROVIDE (_edata = .); 
    PROVIDE (edata = .);
    . = .;
    
    /* BSS */
    PROVIDE (__bss_start = .);
    PROVIDE (__bss_start__ = .);
    .bss            :
    {
        *(.dynbss)
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
        . = ALIGN(. != 0 ? 32 / 8 : 1);
    }
    PROVIDE (_bss_end__ = .);
    PROVIDE (__bss_end__ = .);
    
    . = ALIGN(32 / 8);
    . = SEGMENT_START("ldata-segment", .);
    . = ALIGN(32 / 8);
    
    PROVIDE (__end__ = .);
    PROVIDE (_end = .); 
    PROVIDE (end = .);
    
    . = DATA_SEGMENT_END (.);
    /* DWARF debug sections.
       Symbols in the DWARF debugging sections are relative to the beginning
       of the section so we begin them at 0.  */
    /* DWARF 1.  */
    .debug          0 : { *(.debug) }
    .line           0 : { *(.line) }
    /* GNU DWARF 1 extensions.  */
    .debug_srcinfo  0 : { *(.debug_srcinfo) }
    .debug_sfnames  0 : { *(.debug_sfnames) }
    /* DWARF 1.1 and DWARF 2.  */
    .debug_aranges  0 : { *(.debug_aranges) }
    .debug_pubnames 0 : { *(.debug_pubnames) }
    /* DWARF 2.  */
    .debug_info     0 : { *(.debug_info .gnu.linkonce.wi.*) }
    .debug_abbrev   0 : { *(.debug_abbrev) }
    .debug_line     0 : { *(.debug_line .debug_line.* .debug_line_end) }
    .debug_frame    0 : { *(.debug_frame) }
    .debug_str      0 : { *(.debug_str) }
    .debug_loc      0 : { *(.debug_loc) }
    .debug_macinfo  0 : { *(.debug_macinfo) }
    /* SGI/MIPS DWARF 2 extensions.  */
    .debug_weaknames 0 : { *(.debug_weaknames) }
    .debug_funcnames 0 : { *(.debug_funcnames) }
    .debug_typenames 0 : { *(.debug_typenames) }
    .debug_varnames  0 : { *(.debug_varnames) }
    /* DWARF 3.  */
    .debug_pubtypes 0 : { *(.debug_pubtypes) }
    .debug_ranges   0 : { *(.debug_ranges) }
    /* DWARF 5.  */
    .debug_addr     0 : { *(.debug_addr) }
    .debug_line_str 0 : { *(.debug_line_str) }
    .debug_loclists 0 : { *(.debug_loclists) }
    .debug_macro    0 : { *(.debug_macro) }
    .debug_names    0 : { *(.debug_names) }
    .debug_rnglists 0 : { *(.debug_rnglists) }
    .debug_str_offsets 0 : { *(.debug_str_offsets) }
    .debug_sup      0 : { *(.debug_sup) }
    .gnu.attributes 0 : { KEEP (*(.gnu.attributes)) }
    .note.gnu.arm.ident 0 : { KEEP (*(.note.gnu.arm.ident)) }
    /DISCARD/ : { *(.note.GNU-stack) *(.gnu_debuglink) *(.gnu.lto_*) }
}
