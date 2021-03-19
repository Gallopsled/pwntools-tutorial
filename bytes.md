# Bytes vs. Strings

When Pwntools was originally (re-)written, about a decade ago, Python2 was the bee's knees.

```
commit e692277db8533eaf62dd3d2072144ccf0f673b2e
Author: Morten Brøns-Pedersen <mortenbp@gmail.com>
Date:   Thu Jun 7 17:34:48 2012 +0200

    ALL THE THINGS
```

Many exploits written over the years in Python assume that a `str` object has a 1:1 mapping with a `bytes` object, because this is How Things Work™️ on Python2.  In this section, we discuss some of the changes necessary to write exploits on Python3, versus their Python2 counterparts.

## Python2

In Python2, the class `str` is literally the same class as `bytes`, and there is a 1:1 mapping.  There is never a need to call `encode` or `decode` on anything -- text is bytes, bytes are text.

This is incredibly convenient for writing exploits, since you can just write `"\x90\x90\x90\x90"` to get a NOP sled.  All of Pwntools tubes and data manipulation on Python2 support either strings or bytes.

Nobody ever used `unicode` objects to write exploits, so unicode-to-bytes transformations were extremely rare.

## Python3

In Python3, the `unicode` class is effectively the `str` class.  This has a few immediate and obvious ramifications.

At first glance, Python3 seems to make things harder, because `bytes` declares individual octets (as the name `bytes` implies) while `str` is used for any text-based representation of data.

Pwntools goes through great lengths to follow the "principle of least surprise" -- that is, things behave the way you expect them to.

```
>>> r.send('❤️')
[DEBUG] Sent 0x6 bytes:
    00000000  e2 9d a4 ef  b8 8f                                  │····│··│
    00000006
>>> r.send('\x00\xff\x7f\x41\x41\x41\x41')
[DEBUG] Sent 0x7 bytes:
    00000000  00 ff 7f 41  41 41 41                               │···A│AAA│
    00000007
```

However, sometimes things break down a bit.  Note here how 99f7e2 gets converted to c299c3b7c3a2.

```
>>> shellcode = "\x99\xf7\xe2"
>>> print(hexdump(flat("padding\x00", shellcode)))
00000000  70 61 64 64  69 6e 67 00  c2 99 c3 b7  c3 a2        │padd│ing·│····│··│
0000000e
```

This happens because the text-string "\x99\xf7\xe2" is automatically converted to UTF-8 code points.  This is not likely what the author wanted.  

Consider instead, with a `b` prefix:

```
>>> shellcode = b"\x99\xf7\xe2"
>>> print(hexdump(flat(b"padding\x00", shellcode)))
00000000  70 61 64 64  69 6e 67 00  99 f7 e2                  │padd│ing·│···│
0000000b
```

Much better!

Generally, the fix for things in Pwntools on Python3 is to make sure all of your strings have a `b` prefix.  This resolves ambiguities and makes everything straightforward.

### Gotchas

There is one "gotcha" worth mentioning about Python3 `bytes` objects.  When iterating over them, you get integers, instead of `bytes` objects.  This is a huge diversion from Python2, and a major annoyance.

```
>>> x=b'123'
>>> for i in x:
...     print(i)
...
49
50
51
```

To work around this, we suggest using slices, which produce length-1 `bytes` objects.

```
>>> for i in range(len(x)):
...     print(x[i:i+1])
...
b'1'
b'2'
b'3'
```

