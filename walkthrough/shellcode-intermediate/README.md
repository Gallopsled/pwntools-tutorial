# shellcode

**Note**: You should check out the [basic shellcode tutorial first](../shellcode-basic/README.md)!

Now that you've seen all of the tools available to you on the command-line, it's easy to learn about their Python counterparts.

## `asm`

The `asm` tool works pretty much the same way.

```python
from pwn import *

nop = asm('nop')
arm_nop = asm('nop', arch='arm')
```

Like most other things in Pwntools, it's aware of the settings in `context`.

```python
context.arch = 'powerpc'
powerpc_nop = asm('nop')
```

## `disasm`

The `disasm` tool also works pretty much the same way.

```python
from pwn import *

print disasm('\x90')
# nop

print disasm('\xff\x00\x40\xe3', arch='arm')
#    0:   e34000ff        movt    r0, #255        ; 0xff
```

## `shellcraft`

The shellcraft module also works pretty much the same way.  By default, the `shellcraft` module uses the currently-active OS and architecture from the `context` settings.

Alternately, you can directly invoke a specific template by its full path.

```python
from pwn import *

print shellcraft.sh()
#    /* push '/bin///sh\x00' */
#    push 0x68
#    push 0x732f2f2f
#    push 0x6e69622f
#
#    /* call execve('esp', 0, 0) */
#    mov ebx, esp
#    xor ecx, ecx
#    push 0xb
#    pop eax
#    cdq /* Set edx to 0, eax is known to be positive */
#    int 0x80

context.arch = 'arm'
# print shellcraft.sh()
#     adr r0, bin_sh
#     mov r2, #0
#     push {r0, r2}
#     mov r1, sp
#     svc SYS_execve
# bin_sh: .asciz "/bin/sh"


# Can also be explicitly invoked directly by path.
print shellcraft.i386.linux.sh()
```

Functions which take arguments work exactly like normal functions.

```python
from pwn import *

print shellcraft.pushstr("Hello!")
#    /* push 'Hello!\x00' */
#    push 0x1010101
#    xor dword ptr [esp], 0x101206e
#    push 0x6c6c6548

print shellcraft.pushstr("Goodbye!")
#    /* push 'Goodbye!\x00' */
#    push 0x1
#    dec byte ptr [esp]
#    push 0x21657962
#    push 0x646f6f47
```