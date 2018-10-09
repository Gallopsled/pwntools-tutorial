# Pwntools Tutorials

This repository contains some basic tutorials for getting started with pwntools (and pwntools).

These tutorials do not make any effort to explain reverse engineering or exploitation primitives, but assume this knowledge.

# Introduction

[`Pwntools`](https://pwntools.com) is a grab-bag of tools to make exploitation during CTFs as painless as possible, and to make exploits as easy to read as possible.

There are bits of code everyone has written a million times, and everyone has their own way of doing it.  Pwntools aims to provide all of these in a semi-standard way, so that you can stop copy-pasting the same `struct.unpack('>I', x)` code around and instead use more slightly more legible wrappers like `pack` or `p32` or even `p64(..., endian='big', sign=True)`.

Aside from convenience wrappers around mundane functionality, it also provides a very rich set of `tubes` which wrap all of the IO that you'll ever perform in a single, unifying interface.  Switching from a local exploit to a remote exploit, or local exploit over SSH becomes a one-line change.

Last but not least, it also includes a wide array of exploitation assistance tools for intermediate-to-advanced use cases.  These include remote symbol resolution given a memory disclosure primitive (`MemLeak` and `DynELF`), ELF parsing and patching (`ELF`), and ROP gadget discovery and call-chain building (`ROP`).

# Table of Contents

- [Installing Pwntools](installing.md)
- [Tubes](tubes.md)
    + Basic Tubes
    + Interactive Shells
    + Processes
    + Networking
    + Secure Shell
    + Serial Ports
- [Utility](utility.md)
    + Encoding and Hashing
    + Packing / unpacking integers
    + Pattern generation
    + Safe evaluation
- [Context](context.md)
    + Architecture
    + Endianness
    + Log verbosity
    + Timeout
- [ELFs](elf.md)
    + Reading and writing
    + Patching
    + Symbols
- [Assembly](assembly.md)
    + Assembling shellcode
    + Disassembling bytes
    + Shellcraft library
    + Constants
- [Debugging](debugging.md)
    + Debugging local processes
    + Breaking at the entry point
    + Debugging shellcode
- [ROP](rop.md)
    + Dumping gadgets
    + Searching for gadgets
    + ROP stack generation
    + Helper functions
- [Logging](logging.md)
    + Basic logging
    + Log verbosity
    + Progress spinners
- [Leaking Remote Memory](leaking.md)
    + Declaring a leak function
    + Leaking arbitrary memory
    + Remote symbol resolution
