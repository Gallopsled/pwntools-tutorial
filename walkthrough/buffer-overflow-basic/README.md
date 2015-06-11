# Basic Buffer Overflow

This directory is the most basic, classic, stack-based buffer overflow.

The stack is executable, and the binary is not randomized.

A few things are demonstrated in this example:

- `process` tube
- `gdb.attach` for debugging processes
- `ELF` for searching for assembly instructions
- `cyclic` and `cyclic_find` for calculating offsets
- `pack` for packing integers into byte strings
- `asm` for assembling shellcode
- `shellcraft` for providing a shellcode library
- `tube.interactive` for enjoying your shell

Feel free to modify the example, and try some other shellcode snippet!

You can easily list the available shellcode from the command-line:

```
$ shellcraft | grep i386
...
i386.linux.execve
...
```
