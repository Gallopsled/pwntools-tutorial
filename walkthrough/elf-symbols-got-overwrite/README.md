# ELF Symbol Lookups and GOT Overwrites

This is a position-independent binary which gives you a module address, and a trivial write-what-where.

The exploit demonstrates how to perform symbol lookups in the GOT, PLT, and other exported symbols.  It also shows how to rebase the module when its actual base address is different from the ELF's base address (e.g. PIE).

Also as an added tip, it demonstrates the `context.binary` field, which not only automatically loads an ELF, but also automagically sets the `context.arch`, `context.bits`, and `context.endianness` variables to the appropriate ones.