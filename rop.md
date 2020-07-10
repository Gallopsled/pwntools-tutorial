Table of Contents
=================

  * [Background](#background)
  * [Loading an ELF](#loading-an-elf)
  	* [Fixing Addresses](#fixing-addresses)
  * [Inspecting Gadgets](#inspecting-gadgets)
  * [Viewing All Gadgets](#viewing-all-gadgets)
  	* [Really viewing *ALL* Gadgets](#really-viewing-all-gadgets)
  * [Adding Raw Data](#adding-raw-data)
  * [Dumping ROP stacks](#dumping-rop-stacks)
  * [Extracting Raw Bytes](#extracting-raw-bytes)
  * [Calling Functions Magically](#calling-functions-manually)
  	* [Calling Functions by Name](#calling-functions-by-name)
  * [Multiple ELFs](#multiple-elfs)
  * [Getting a shell](#getting-a-shell)


# Background

Return-oriented programming (ROP) is a technique for bypassing NX (no-execute, also known as Data Execution Prevention (DEP)).

Pwntools has several features that make ROP exploitation simpler, but only works on i386 and amd64 architectures.

# Loading an ELF

To create a `ROP` object, just pass it an `ELF` file.

```py
elf = ELF('/bin/sh')
rop = ROP(elf)
```

This will automatically load the binary, and extract most simple gadgets from it.  For example, if you want to load the `rbx` register:

```
rop.rbx
# Gadget(0x5fd5, ['pop rbx', 'ret'], ['rbx'], 0x8)
```

## Fixing Addresses

Here we can see the address of the gadget, the contents of its disassembly, what register it loads, and by how much the stack is adjusted when the gadget is executed.

Since in our example, `/bin/sh` is position-independent (i.e. uses ASLR), we can adjust the load address on the ELF object first.

```
elf.address = 0xff000000
rop = ROP(elf)
rop.rbx
# Gadget(0xff005fd5, ['pop rbx', 'ret'], ['rbx'], 0x8)
```

# Inspecting Gadgets

You can ask the ROP object how to load any register you want, through magic accessors.  We used `rbx` above, but we can also look for other registers.

```
rop.rbx
# Gadget(0xff005fd5, ['pop rbx', 'ret'], ['rbx'], 0x8)
```

If the register cannot be loaded, the return value is `None`.  In our example, there are no `pop rcx; ret` gadgets for example.

```
rop.rcx
# None
```

## Viewing All Gadgets

Pwntools intentionally excludes most non-trivial gadgets, but you can see a list of what it has loaded by looking at the `ROP.gadgets` property, which maps the address of  a gadget to the gadget itself.

```
rop.gadgets
# {4278225723: Gadget(0xff008b3b, ['add esp, 0x10', 'pop rbx', 'pop rbp', 'pop r12', 'ret'], ['rbx', 'rbp', 'r12'], 0x20),
#  4278278088: Gadget(0xff0157c8, ['add esp, 0x130', 'pop rbp', 'ret'], ['rbp'], 0x138),
#  4278284789: Gadget(0xff0171f5, ['add esp, 0x138', 'pop rbx', 'pop rbp', 'ret'], ['rbx', 'rbp'], 0x144),
#  4278272966: Gadget(0xff0143c6, ['add esp, 0x18', 'ret'], [], 0x1c),
#  4278239612: Gadget(0xff00c17c, ['add esp, 0x20', 'pop rbx', 'pop rbp', 'pop r12', 'ret'], ['rbx', 'rbp', 'r12'], 0x30),
#  4278259611: Gadget(0xff010f9b, ['add esp, 0x28', 'pop rbp', 'pop r12', 'ret'], ['rbp', 'r12'], 0x34),
# ...
#  4278216828: Gadget(0xff00687c, ['pop rsp', 'pop r13', 'ret'], ['rsp', 'r13'], 0xc),
#  4278214225: Gadget(0xff005e51, ['pop rsp', 'ret'], ['rsp'], 0x8),
#  4278210586: Gadget(0xff00501a, ['ret'], [], 0x4)}
```

## Really Viewing *ALL* Gadgets

 Pwntools ROP filters out non-trivial gadgets, so if it doesn't have something you want, we recommend using ROPGadget to inspect the binary.

# Adding Raw Data

In order to add raw data to the ROP stack, simply call `ROP.raw()`.

```py
rop.raw(0xdeadbeef)
rop.raw(0xcafebabe)
rop.raw('asdf')
```

# Dumping ROP stacks

Now that we have some gadgets, let's look at what's on the ROP stack:

```py
print(rop.dump())
# 0x0000:       0xdeadbeef
# 0x0004:       0xcafebabe
# 0x0008:          b'asdf' 'asdf'
```

# Extracting the Raw Bytes

Now that we have a ROP stack, we want the raw bytes out of it.  Use the `bytes()` method  to do this.

```py
print(hexdump(bytes(rop)))
# 00000000  ef be ad de  be ba fe ca  61 73 64 66               │····│····│asdf│
# 0000000c
```

# Calling Functions Magically

The real power of Pwntools' ROP tooling is the ability to invoke arbitrary functions, either via magic accessors or via the `ROP.call()` routine.

```
elf = ELF('/bin/sh')
rop = ROP(elf)
rop.call(0xdeadbeef, [0, 1])
print(rop.dump())
# 0x0000:       0xdeadbeef 0xdeadbeef(0, 1, 2, 3)
# 0x0004:          b'baaa' <return address>
# 0x0008:              0x0 arg0
# 0x000c:              0x1 arg1
```

Notice here that it's using a 32-bit ABI, which is not correct.  We can also do ROP against 64-bit binaries, but we need to set `context.arch` accordingly.  We can use `context.binary` to do this automagically.

```
context.binary = elf = ELF('/bin/sh')
rop = ROP(elf)
rop.call(0xdeadbeef, [0, 1])
print(rop.dump())
# 0x0000:           0x61aa pop rdi; ret
# 0x0008:              0x0 [arg0] rdi = 0
# 0x0010:           0x5f73 pop rsi; ret
# 0x0018:              0x1 [arg1] rsi = 1
# 0x0020:       0xdeadbeef
```

# Calling Functions by Name

If your library has a function you want to call in its GOT/PLT, or there are symbols for the binary, you can invoke function names directly.

```
context.binary = elf = ELF('/bin/sh')
rop = ROP(elf)
rop.execve(0xdeadbeef)
print(rop.dump())
# 0x0000:           0x61aa pop rdi; ret
# 0x0008:       0xdeadbeef [arg0] rdi = 3735928559
# 0x0010:           0x5824 execve
```

# Multiple ELFs

Generally, more than one ELF is available in the address space of your process at a time.  Let's look at an example that uses `/bin/sh` as well as its `libc`.  Originally, we looked at `rop.rcx` and it was `None`, since there is no `pop rcx; ret` gadget in bash.  However, now we have all of the gadgets from `libc` available as well.

```py
context.binary = elf = ELF('/bin/sh')
libc = elf.libc

elf.address = 0xAA000000
libc.address = 0xBB000000

rop.rax
# Gadget(0xaa00eb87, ['pop rax', 'ret'], ['rax'], 0x10)
rop.rbx
# Gadget(0xaa005fd5, ['pop rbx', 'ret'], ['rbx'], 0x10)
rop.rcx
# Gadget(0xbb09f822, ['pop rcx', 'ret'], ['rcx'], 0x10)
rop.rdx
# Gadget(0xbb117960, ['pop rdx', 'add rsp, 0x38', 'ret'], ['rdx'], 0x48)
```

Notice how the `rax` and `rbx` gadgets are in the main binary (0xAA...) while the second two are in libc (0xBB...).

Now let's do a more complex call!

```py
rop.memcpy(0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc)
print(rop.dump())
# 0x0000:       0xbb11c1e1 pop rdx; pop r12; ret
# 0x0008:       0xcccccccc [arg2] rdx = 3435973836
# 0x0010:      b'eaaafaaa' <pad r12>
# 0x0018:       0xaa0061aa pop rdi; ret
# 0x0020:       0xaaaaaaaa [arg0] rdi = 2863311530
# 0x0028:       0xaa005f73 pop rsi; ret
# 0x0030:       0xbbbbbbbb [arg1] rsi = 3149642683
# 0x0038:       0xaa0058a4 memcpy
```

Note that Pwntools was able to use the `pop rdx; pop r12; ret` gadget, and account for the extra value needed on the stack.   Also note that the symbolic value of each item is listen  in `rop.dump()`.  For  example, it shows that we are settings rdx=3435973836.

# Getting a shell

Sometimes, getting a shell can be pretty easy!  Let's call `execve` directly, and find an instance of `"/bin/sh\x00"` to pass as the first argument from somewhere within memory.

```py
context.binary = elf = ELF('/bin/sh')
libc = elf.libc

elf.address = 0xAA000000
libc.address = 0xBB000000

rop = ROP([elf, libc])

binsh = next(libc.search(b"/bin/sh\x00"))
rop.execve(binsh, 0, 0)
```

Show our ROP stack

```py
print(rop.dump())
# 0x0000:       0xbb11c1e1 pop rdx; pop r12; ret
# 0x0008:              0x0 [arg2] rdx = 0
# 0x0010:      b'eaaafaaa' <pad r12>
# 0x0018:       0xaa0061aa pop rdi; ret
# 0x0020:       0xbb1b75aa [arg0] rdi = 3139138986
# 0x0028:       0xaa005f73 pop rsi; ret
# 0x0030:              0x0 [arg1] rsi = 0
# 0x0038:       0xaa005824 execve
```

Extract the raw bytes for the ROP

```py
print(hexdump(bytes(rop)))
# 00000000  e1 c1 11 bb  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
# 00000010  65 61 61 61  66 61 61 61  aa 61 00 aa  00 00 00 00  │eaaa│faaa│·a··│····│
# 00000020  aa 75 1b bb  00 00 00 00  73 5f 00 aa  00 00 00 00  │·u··│····│s_··│····│
# 00000030  00 00 00 00  00 00 00 00  24 58 00 aa  00 00 00 00  │····│····│$X··│····│
# 00000040
```
