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
}
