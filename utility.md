# Utility Functions

About half of Binjitsu is utility functions so that you no longer need to copy paste things like this around:

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

## File I/O

A single function call and it does what you want it to.

```py
from pwn import *

write('filename', 'data')
read('filename')
# 'data'
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

## Packing and Unpacking Integers

## Patten Generation

## Safe Evaluation