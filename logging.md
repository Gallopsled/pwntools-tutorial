Table of Contents
=================

  * [Logging](#logging)
  	* [Functions](#functions)
    * [Command Line](#command-line)
    * [Context](#context)
    * [Tubes](#tubes)
    * [Scoped](#scoped)

# Logging

Pwntools has a rich internal debugging system, available for your own debugging
as well as figuring out what's happening behind-the-scenes in Pwntools

## Functions

The logging functionality is exposed when you import `from pwn import *`.
This exposes these routines:

* `error`
* `warn`
* `info`
* `debug`

For example:

```py
>>> warn('Warning!')
[!] Warning!
>>> info('Info!')
[*] Info!
>>> debug('Debug!')
```

Note that the last line is not shown by default, since the default log-level
is "info".

You can use these in your exploit scripts instead of `print` which lets
you dial in the exact amount of debugging information you see.

You can control which log messages are visible in a variety of ways,
all which are explained below.

## Command Line

The easiest way to turn on the maximum amount of logging verbosity is to
run your script with the magic argument `DEBUG`, e.g.

```
$ python exploit.py DEBUG
```

This is useful for seeing the exact bytes being sent / received, and things
that are happening internal to pwntools to make your exploit work.

## Context

You can also set the logging verbosity via `context.log_level`, in the same way
that you set e.g. the target architecture.
This controls all logging statements in the same way as on the command-line.

```py
>>> context.log_level = 'debug'
```

### `log_console`

By default, all logs go to STDOUT.  If you want to change this to a different file, 
e.g. STDERR, you can do this with the `log_console` setting.

```py
>>> context.log_console = sys.stderr
```

### `log_file`

Sometimes you want your logs to go to a specific file, e.g. `log.txt`, to look at later.
You can add a log file by setting `context.log_file`.

```py
>>> context.log_file = './log.txt'
```

## Tubes

Each tube can have its logging verbosity controlled individually, when it is created.
Simply pass `level='...'` to the construction of the object.

```py
>>> io = process('sh', level='debug')
[x] Starting local process '/usr/bin/sh' argv=[b'sh']
[+] Starting local process '/usr/bin/sh' argv=[b'sh'] : pid 34475
>>> io.sendline('echo hello')
[DEBUG] Sent 0xb bytes:
    b'echo hello\n'
>>> io.recvline()
[DEBUG] Received 0x6 bytes:
    b'hello\n'
b'hello\n'
```

This works for all of the tubes (`process`, `remote`, etc), and also works for 
tube-like things (e.g. `gdb.attach` and `gdb.debug`) as well as many other 
routines.

For example, if you want to see *exactly* how some shellcode is assembled:

```py
>>> asm('nop', log_level='debug')
[DEBUG] cpp -C -nostdinc -undef -P -I/home/user/pwntools/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    nop
[DEBUG] /usr/bin/x86_64-linux-gnu-as -32 -o /tmp/user/pwn-asm-0yy12n6i/step2 /tmp/user/pwn-asm-0yy12n6i/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/user/pwn-asm-0yy12n6i/step3 /tmp/user/pwn-asm-0yy12n6i/step4
b'\x90'
```

## Scoped

Sometimes you want ALL the logs to be enabled, but only for part of an exploit script.
You can manually toggle `context.log_level`, or you can use a scoped helper.

```py
io = process(...)
with context.local(log_level='debug'):
	# Things inside the 'with' block are logged verbosely
	io.recvall()
```