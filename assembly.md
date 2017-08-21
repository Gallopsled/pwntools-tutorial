Table of Contents
=================

  * [Assembly](#assembly)
    * [Basic Assembly](#basic-assembly)
    * [Canned assembly (shellcraft)](#canned-assembly-shellcraft)
    * [Command-line Tools](#command-line-tools)
      * [asm ](#asm)
      * [disasm ](#disasm)
      * [shellcraft ](#shellcraft)
    * [Foreign Architectures](#foreign-architectures)
      * [Canned Assembly](#canned-assembly)
      * [Command-line Tools](#command-line-tools-1)

# Assembly

Pwntools makes it very easy to perform assembly in almost any architecture, and comes with a wide variety of canned-but-customizable shellcode ready to go out-of-the-box.

In the [`walkthrough`](walkthrough) directory, there are several longer shellcode tutorials.  This page gives you the basics.

## Basic Assembly

The most basic example, is to convert assembly into shellcode.

```py
from pwn import *

print repr(asm('xor edi, edi'))
# '1\xff'

print enhex(asm('xor edi, edi'))
# 31ff
```

## Canned assembly (`shellcraft`)

The `shellcraft` module gives you pre-canned assembly.  It is generally customizable.  The easiest way to find out which `shellcraft` templates exist is to look at the [documentation on RTD](https://pwntools.readthedocs.org/en/latest/shellcraft.html).

```py
from pwn import *
help(shellcraft.sh)
print '---'
print shellcraft.sh()
print '---'
print enhex(asm(shellcraft.sh()))
```
```
Help on function sh in module pwnlib.shellcraft.internal:

sh()
    Execute /bin/sh
---
    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f

    /* call execve('esp', 0, 0) */
    push (SYS_execve) /* 0xb */
    pop eax
    mov ebx, esp
    xor ecx, ecx
    cdq /* edx=0 */
    int 0x80
---
6a68682f2f2f73682f62696e6a0b5889e331c999cd80
```

## Command-line Tools

There are three command-line tools for interacting with assembly:

- `asm`
- `disasm`
- `shellcraft`

### `asm`

The asm tool does what it says on the tin.  It provides several options for formatting the output.  When the output is a terminal, it defaults to hex-encoded.

```
$ asm nop
90
```

When the output is anything else, it writes the raw data.

```
$ asm nop | xxd
0000000: 90                                       .
```

It also takes data on stdin if no instructions are provided on the command line.

```
$ echo 'push ebx; pop edi' | asm
535f
```

Finally, it supports a few different options for specifying the output format, via the `--format` option.  Supported arguments are `raw`, `hex`, `string`, and `elf`.

```
$ asm --format=elf 'int3' > ./int3
$ ./halt
Trace/breakpoint trap (core dumped)
```

### `disasm`

Disasm is the opposite of `asm`.

```
$ disasm cd80
   0:    cd 80                    int    0x80
$ asm nop | disasm
   0:    90                       nop
```

### `shellcraft`

The `shellcraft` command is the command-line interface to the internal `shellcraft` module.  On the command-line, the full context must be specified, in the order of `arch.os.template`.

```
$ shellcraft i386.linux.sh
6a68682f2f2f73682f62696e6a0b5889e331c999cd80
```

## Foreign Architectures

Assembling for a foreign architecture requires that you have an appropriate version of `binutils` installed.  You should see [installing.md](installing.md) for more information on this.  The only change that is necessary is to set the architecture in the global context variable.  You can see more information about `context` in [context.md](context.md).

```py
from pwn import *

context.arch = 'arm'

print repr(asm('mov r0, r1'))
# '\x01\x00\xa0\xe1'

print enhex(asm('mov r0, r1'))
# 0100a0e1
```

### Canned Assembly

The `shellcraft` module automatically switches to the appropriate architecture.

```py
from pwn import *

context.arch = 'arm'

print shellcraft.sh()
print enhex(asm(shellcraft.sh()))
```
```
    adr r0, bin_sh
    mov r2, #0
    mov r1, r2
    svc SYS_execve
bin_sh: .asciz "/bin/sh"

08008fe20020a0e30210a0e10b0000ef2f62696e2f736800
```

### Command-line Tools

You can also use the command line to assemble foreign-arch shellcode, by using the `--context` command-line option.

```
$ asm --context=arm 'mov r0, r1'
0100a0e1
$ shellcraft arm.linux.sh
08008fe20020a0e30210a0e10b0000ef2f62696e2f736800
```
