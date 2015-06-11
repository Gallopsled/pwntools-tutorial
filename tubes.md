# Tubes

Tubes are effectively I/O wrappers for most types of I/O you'll need to perform:

- Local processes
- Remote TCP or UDP connections
- Processes running on a remote server over SSH
- Serial port I/O

This introduction provides a few examples of the functionality provided, but more complex combinations are possible.  See [the full documentation][docs] for more information on how to perform regular expression matching, and connecting tubes together.

## Basic IO

The basic functions that you'll probably want out of your IO are:

- `recv(n)` - Receive any number of available bytes
- `recvline()` - Receive data until a newline is encountered
- `recvuntil(delim)` - Receive data until a delimiter is found
- `recvregex(pattern)` - Receive data until a regex pattern is satisfied
- `recvrepeat(timeout)` - Keep receiving data until a timeout occurs
- `clean()` - Discard all buffered data

- `send(data)` - Sends data
- `sendline(line)` - Sends data plus a newline

- `pack(int)` - Sends a word-size packed integer
- `unpack()` - Receives and unpacks a word-size integer

## Hello Process

In order to create a tube to talk to a process, you just create a `process` object and give it the name of the target binary.

```py
from pwn import *

io = process('sh')
io.sendline('echo Hello, world')
io.recvline()
# 'Hello, world\n'
```

If you need to provide command-line arguments, or set the environment, additional options are available.  See [the full documentation][process] for more information;

```py
from pwn import *

io = process(['sh', '-c', 'echo $MYENV'], env={'MYENV': 'MYVAL'})
io.recvline()
# 'MYVAL\n'
```

## Hello Network

Creating a network connection is also easy, and has the exact same interface.

```py
from pwn import *

io = remote('google.com', 80)
io.send('GET /\r\n\r\n')
io.recvline()
# 'HTTP/1.0 200 OK\r\n'
```

If you need to specify protocol information, it's also pretty straightforward.

```py
from pwn import *

dns  = remote('8.8.8.8', 53, typ='udp')
tcp6 = remote('google.com', 80, fam='ipv6')
```

## Hello SSH

SSH connectivity is similarly simple.  Compare the code below with that in "Hello Process" above.

You can also do more complex things with SSH, such as port forwarding and file upload / download.  See the [SSH tutorial][ssh] for more information.

```py
from pwn import *

session = ssh('bandit0', 'bandit.labs.overthewire.org', password='bandit0')

io = session.process('sh', env={"PS1":""})
io.sendline('echo Hello, world!')
io.recvline()
# 'Hello, world!\n'
```


## Hello Serial

In the event you need to get some local hacking done, there's also a serial tube.  As always, there is more information in the [full online documentation][serial].

```py
from pwn import *

io = serialtube('/dev/ttyUSB0', baudrate=115200)
...
```

[docs]: https://binjitsu.readthedocs.org/en/latest/tubes.html
[process]: https://binjitsu.readthedocs.org/en/latest/tubes/processes.html
[ssh]: ssh.md
[remote]: https://binjitsu.readthedocs.org/en/latest/tubes/sock.html
[serial]: https://binjitsu.readthedocs.org/en/latest/tubes/serial.html
