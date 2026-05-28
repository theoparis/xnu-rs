ENTRY(_start)

PHDRS
{
  rodata PT_LOAD FLAGS(4);
  text PT_LOAD FLAGS(5);
  data PT_LOAD FLAGS(6);
}

SECTIONS
{
  . = 0x48000000;

  .rodata : ALIGN(4K) {
    *(.rodata .rodata.*)
    *(.eh_frame_hdr)
    *(.eh_frame)
  } :rodata

  .text : ALIGN(4K) {
    *(.text._start)
    *(.text .text.*)
  } :text

  .data : ALIGN(4K) {
    *(.data .data.*)
  } :data

  .bss (NOLOAD) : ALIGN(4K) {
    *(.bss .bss.*)
    *(COMMON)
  } :data

  /DISCARD/ : {
    *(.comment)
    *(.note .note.*)
  }
}
