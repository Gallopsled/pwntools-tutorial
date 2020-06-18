Table of Contents
=================

  * [ELFs](#elfs)
    * [Loading ELF files](#loading-elf-files)
    * [Using Symbols](#using-symbols)
    * [Changing the Base Address](#changing-the-base-address)
    * [Reading ELF Files](#reading-elf-files)
    * [Patching ELF Files](#patching-elf-files)
    * [Searching ELF Files](#searching-elf-files)
    * [Building ELF Files](#building-elf-files)
    * [Running and Debugging ELF Files](#running-and-debugging-elf-files)

# ELFs

Pwntools makes interacting with ELF files relatively straightforward, via the `ELF` class.  You can find the full documentation on [RTD](https://pwntools.readthedocs.org/en/latest/elf.html).

## Loading ELF files

ELF files are loaded by path.  Upon being loaded, some security-relevant attributes about the file are printed.

```py
from pwn import *

e = ELF('/bin/bash')
# [*] '/bin/bash'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      No PIE
#     FORTIFY:  Enabled
```

## Using Symbols

ELF files have a few different sets of symbols available, each contained in a dictionary of `{name: data}`.

- `ELF.symbols` lists all known symbols, including those below.  Preference is given the PLT entries over GOT entries.
- `ELF.got` only contains GOT entries
- `ELF.plt` only contains PLT entries
- `ELF.functions` only contains functions (requires DWARF symbols)

This is very useful in keeping exploits robust, by removing the need to hard-code addresses.

```py
from pwn import *

e = ELF('/bin/bash')

print "%#x -> license" % e.symbols['bash_license']
print "%#x -> execve" % e.symbols['execve']
print "%#x -> got.execve" % e.got['execve']
print "%#x -> plt.execve" % e.plt['execve']
print "%#x -> list_all_jobs" % e.functions['list_all_jobs'].address
```

This would print something like the following:

```
0x4ba738 -> license
0x41db60 -> execve
0x6f0318 -> got.execve
0x41db60 -> plt.execve
0x446420 -> list_all_jobs
```

## Changing the Base Address

Changing the base address of the ELF file (e.g. to adjust for ASLR) is very straightforward.  Let's change the base address of `bash`, and see all of the symbols change.

```py
from pwn import *

e = ELF('/bin/bash')

print "%#x -> base address" % e.address
print "%#x -> entry point" % e.entry
print "%#x -> execve" % e.symbols['execve']

print "---"
e.address = 0x12340000

print "%#x -> base address" % e.address
print "%#x -> entry point" % e.entry
print "%#x -> execve" % e.symbols['execve']
```

This should print something like:

```
0x400000 -> base address
0x42020b -> entry point
0x41db60 -> execve
---
0x12340000 -> base address
0x1236020b -> entry point
0x1235db60 -> execve
```

## Reading ELF Files

We can directly interact with the ELF as if it were loaded into memory, using `read`, `write`, and functions named identically to that in the `packing` module.  Additionally, you can see the disassembly via the `disasm` method.

```py
from pwn import *

e = ELF('/bin/bash')

print repr(e.read(e.address, 4))

p_license = e.symbols['bash_license']
license   = e.unpack(p_license)
print "%#x -> %#x" % (p_license, license)

print e.read(license, 14)
print e.disasm(e.symbols['main'], 12)
```

This prints something like:

```
'\x7fELF'
0x4ba738 -> 0x4ba640
License GPLv3+
  41eab0:       41 57                   push   r15
  41eab2:       41 56                   push   r14
  41eab4:       41 55                   push   r13
```

## Patching ELF Files

Patching ELF files is just as simple.

```py
from pwn import *

e = ELF('/bin/bash')

# Cause a debug break on the 'exit' command
e.asm(e.symbols['exit_builtin'], 'int3')

# Disable chdir and just print it out instead
e.pack(e.got['chdir'], e.plt['puts'])

# Change the license
p_license = e.symbols['bash_license']
license = e.unpack(p_license)
e.write(license, 'Hello, world!\n\x00')

e.save('./bash-modified')
```

We can then run our modified version of bash.

```
$ chmod +x ./bash-modified
$ ./bash-modified -c 'exit'
Trace/breakpoint trap (core dumped)
$ ./bash-modified --version | grep "Hello"
Hello, world!
$ ./bash-modified -c 'cd "No chdir for you!"'
/home/user/No chdir for you!
No chdir for you!
./bash-modified: line 0: cd: No chdir for you!: No such file or directory
```

## Searching ELF Files

Every once in a while, you just need to find some byte sequence.  The most common example is searching for e.g. `"/bin/sh\x00"` for an `execve` call.
The `search` method returns an iterator, allowing you to either take the first result, or keep searching if you need something special (e.g. no bad characters in the address).  You can optionally pass a `writable` argument to `search`, indicating it should only return addresses in writable segments.

```py
from pwn import *

e = ELF('/bin/bash')

for address in e.search('/bin/sh\x00'):
    print hex(address)
```

The above example prints something like:

```
0x420b82
0x420c5e
```

## Building ELF Files

ELF files can be created from scratch relatively easy.  All of these functions are context-aware.  The relevant functions are `from_bytes` and `from_assembly`.  Each returns an `ELF` object, which can easily be saved to file.

```
from pwn import *

ELF.from_bytes('\xcc').save('int3-1')
ELF.from_assembly('int3').save('int3-2')
ELF.from_assembly('nop', arch='powerpc').save('powerpc-nop')
```

## Running and Debugging ELF Files

If you have an `ELF` object, you can run or debug it directly.  The following are equivalent:

```py
>>> io = elf.process()
# vs
>>> io = process(elf.path)
```

Similarly, you can launch a debugger trivially attached to your ELF.  This is super useful when testing shellcode, without the need for a C wrapper to load and debug it.

```py
>>> io = elf.debug()
# vs
>>> io = gdb.debug(elf.path)
```