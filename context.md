Table of Contents
=================

  * [Context](#context)
    * [Context Settings](#context-settings)
      * [arch](#arch)
      * [bits](#bits)
      * [binary](#binary)
      * [endian](#endian)
      * [log_file](#log_file)
      * [log_level](#log_level)
      * [sign](#sign)
      * [terminal](#terminal)
      * [timeout](#timeout)
      * [update](#update)

# Context

The `context` object is a global, thread-aware object which contains various settins used by `pwntools`.

Generally at the top of an exploit, you'll find something like:

```py
from pwn import *
context.arch = 'amd64'
```

Which informs pwntools that shellcode generated will be for `amd64`, and that the default word size is 64 bits

## Context Settings

### arch

The target architecture.  Valid values are `"aarch64"`, `"arm"`, `"i386"`, `"amd64"`, etc.  The default is `"i386"`.

The first time this is set, it automatically sets the default `context.bits` and `context.endian` to the most likely values.

### bits

How many bits make up a word in the target binary, e.g. 32 or 64.

### binary

Absorb settings from an ELF file.  For example, `context.binary='/bin/sh'`.

### endian

Set to `"big"` or `"little"` (the default) as needed.

### log_file

File to send all of the logging output into.

### log_level

Verbosity of logs.  Valid values are integers (lower is more verbose), and string values like `"debug"`, `"info"`, and `"error"`.

### sign

Sets the default signed-ness of integer packing / unpacking.  Default is `"unsigned"`.

### terminal

Preferred terminal program to open new windows with.  By default, uses `x-terminal-emulator` or `tmux`.

### timeout

Default timeout for tube operations.

### update

Sets multiple values at once, e.g. `context.update(arch='mips', bits=64, endian='big')`.
