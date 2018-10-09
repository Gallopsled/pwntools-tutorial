Table of Contents
=================

  * [Utility Functions](#utility-functions)
    * [Packing and Unpacking Integers](#packing-and-unpacking-integers)
    * [File I/O](#file-io)
    * [Hashing and Encoding](#hashing-and-encoding)
        * [Base64](#base64)
        * [Hashes](#hashes)
        * [URL Encoding](#url-encoding)
        * [Hex Encoding](#hex-encoding)
        * [Bit Manipulation and Hex Dumping](#bit-manipulation-and-hex-dumping)
        * [Hex Dumping](#hex-dumping)
    * [Patten Generation](#patten-generation)

# Utility Functions

About half of Pwntools is utility functions so that you no longer need to copy paste things like this around:

```py
import struct

def p(x):
    return struct.pack('I', x)
def u(x):
    return struct.unpack('I', x)[0]

1234 == u(p(1234))
```

Instead, you just get nice little wrappers.  As an added bonus, everything is a bit more legible and easier to understand when reading someone else's exploit code.

```py
from pwn import *

1234 == unpack(pack(1234))
```

## Packing and Unpacking Integers

This is probably the most common thing you'll do, so it's at the top.  The main `pack` and `unpack` functions are aware of the global settings in [`context`](context.md) such as `endian`, `bits`, and `sign`.

You can also specify them explitily in the function call.

```py
pack(1)
# '\x01\x00\x00\x00'

pack(-1)
# '\xff\xff\xff\xff'

pack(2**32 - 1)
# '\xff\xff\xff\xff'

pack(1, endian='big')
# '\x00\x00\x00\x01'

p16(1)
# '\x01\x00'

hex(unpack('AAAA'))
# '0x41414141'

hex(u16('AA'))
# '0x4141'
```

## File I/O

A single function call and it does what you want it to.

```py
from pwn import *

write('filename', 'data')
read('filename')
# 'data'
read('filename', 1)
# 'd'
```

## Hashing and Encoding

Quick access to lots of functions to transform your data into whatever format you need it in.

#### Base64

```py
'hello' == b64d(b64e('hello'))
```

#### Hashes

```py
md5sumhex('hello') == '5d41402abc4b2a76b9719d911017c592'
write('file', 'hello')
md5filehex('file') == '5d41402abc4b2a76b9719d911017c592'
sha1sumhex('hello') == 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
```

#### URL Encoding

```py
urlencode("Hello, World!") == '%48%65%6c%6c%6f%2c%20%57%6f%72%6c%64%21'
```

#### Hex Encoding

```py
enhex('hello')
# '68656c6c6f'
unhex('776f726c64')
# 'world'
```

#### Bit Manipulation and Hex Dumping

```py
bits(0b1000001) == bits('A')
# [0, 0, 0, 1, 0, 1, 0, 1]
unbits([0,1,0,1,0,1,0,1])
# 'U'
```

#### Hex Dumping

```py
print hexdump(read('/dev/urandom', 32))
# 00000000  65 4c b6 62  da 4f 1d 1b  d8 44 a6 59  a3 e8 69 2c  │eL·b│·O··│·D·Y│··i,│
# 00000010  09 d8 1c f2  9b 4a 9e 94  14 2b 55 7c  4e a8 52 a5  │····│·J··│·+U|│N·R·│
# 00000020
```

## Pattern Generation

Pattern generation is a very handy way to find offsets without needing to do math.

Let's say we have a straight buffer overflow, and we generate a pattern and provide it to the target application.

```py
io = process(...)
io.send(cyclic(512))
```

In the core dump, we might see that the crash occurs at 0x61616178.  We can avoid needing to do any analysis of the crash frame by just punching that number back in and getting an offset.

```py
cyclic_find(0x61616178)
# 92
```
