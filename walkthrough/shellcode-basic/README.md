# shellcode

Every once in a while, you'll need to run some shellcode.

Before jumping into how to do things in Python with pwntools, it's worth exploring the command-line tools as they can really make life easy!

## `asm`

This command line tool does what it says on the tin.

```sh
$ asm nop
90
$ asm 'mov eax, 0xdeadbeef'
b8efbeadde
```

There are a few output formats to choose from.  By default, the tool writes hex-encoded output to stdout if it's a terminal.  If it's a pipe or file, it will instead just write the binary data.

`phd` is a command that comes with pwntools which is very similar to `xxd`, but includes highlighting of printable ASCII values, NULL bytes, and some other special values.

```sh
$ asm nop -f hex
90
$ asm nop -f string
'\x90'
$ asm nop | phd
00000000  90                                                  │·│
00000001
```

Different architectures and endianness values can be selected as well, as long as you have an appropriate version of `binutils` installed.  See the [installation](installation.md) page for more information.

```sh
$ asm -c arm nop
00f020e3
$ asm -c powerpc nop
60000000
$ asm -c mips nop
00000000
```

Pwntools is also aware of most common constants, and resolves them in a context-sensitive manner.

```sh
$ asm 'push SYS_execve'
6a0b
$ asm -c amd64 'push SYS_execve'
6a3b
```

## `disasm`

Disasm is the counterpart to `asm`.

```sh
$ asm 'push eax' | disasm
   0:   50                      push   eax
$ asm -c arm 'bx lr' | disasm -c arm
   0:   e12fff1e        bx      lr
```

## `shellcraft`

Shellcraft is the command-line interface to the shellcode library that comes with Pwntools.  To get a list of all avialable shellcode, just use the `shellcraft` command by itself.

```sh
$ shellcraft
aarch64.linux.accept
aarch64.linux.access
aarch64.linux.acct
...
```

Many of the shellcraft templates are just syscall wrappers, designed to make shellcode easier.  A few of them -- in particular `sh`, `dupsh`, and `echo` -- are compact implementations of common shellcode for `execve`, `dup2`ing file descriptors, and writing a string to `stdout`.

Like the `asm` tool, `shellcraft` has multiple output modes.

```sh
$ shellcraft i386.linux.sh
6a68682f2f2f73682f62696e89e331c96a0b5899cd80
$ shellcraft i386.linux.sh -fasm
    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f

    /* call execve('esp', 0, 0) */
    mov ebx, esp
    xor ecx, ecx
    push 0xb
    pop eax
    cdq /* Set edx to 0, eax is known to be positive */
    int 0x80
```

## Debugging Shellcode

Invariably, you'll want to debug your shellcode, or just experiment with a small snippet.  Pwntools makes this super easy!

### Emitting ELF files

The first option is to emit an ELF file which contains the shellcode, and load it in GDB manually.

```sh
$ shellcraft i386.linux.sh -f elf > sh
$ asm 'mov eax, 1; int 0x80' -f elf > exit
$ chmod +x sh exit
$ strace ./exit
execve("./exit", ["./exit"], [/* 94 vars */]) = 0
_exit(0)                                = ?
$ echo 'echo Hello!' | strace -e execve ./sh
execve("./sh", ["./sh"], [/* 94 vars */]) = 0
execve("/bin///sh", [0], [/* 0 vars */]) = 0
Hello!
```

Some of the commands may take options, and all of them should be documented.  `shellcraft` will also resolve any constants it knows about.

```sh
$ shellcraft i386.linux.echo -?
Writes a string to a file descriptor

Arguments:
    string(str): Message to print
    sock: File descriptor.  Default is ebp.
$ shellcraft i386.linux.echo "Hello, world" STDOUT_FILENO
686f726c64686f2c20776848656c6c6a015b89e16a0c5a6a0458cd80
$ shellcraft i386.linux.mov eax SYS_execve -fasm
    push 0xb
    pop eax
$ shellcraft i386.linux.mov eax SYS_execve
6a0b58
```

### Launching GDB

Instead of emitting an ELF and launching GDB manually, you can just jump straight into GDB.

```sh
$ shellcraft i386.linux.sh --debug
$ asm 'mov eax, 1; int 0x80;' --debug
```
