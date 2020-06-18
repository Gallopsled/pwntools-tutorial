Table of Contents
=================

  * [Prerequisites](#prerequisites)
  * [Launching a Process Under GDB](#launching-a-process-under-gdb)
  * [Attaching to a Running Process](#attaching-to-a-running-process)
	  * [Local Processes](#local-processes)
	  * [Forking Servers](#forking-servers)
  * [Debugging Foreign Architectures](#debugging-foreign-architectures)
  * [Troubleshooting](#troubleshooting)
	  * [Behind the Scenes](#behind-the-scenes)
	  * [Specifying a Terminal Window](#specifying-a-terminal-window)
	  * [Environment Variables](#environment-variables)
	  * [Unable to Attach to Processes](#unable-to-attach-to-processes)
	  * [argv0 and argc==0](#argv0-and-argc==0)

Pwntools has rich support for using a debugger in your exploit workflow, and debuggers
are very useful when developing exploits when issues with exploits arise.

In addition to the resources here for debugging, you may want to enhance your GDB
experience with one of the following projects:

* [Pwndbg](https://pwndbg.re)
* [GDB Enhanced Features (GEF)](https://github.com/hugsy/gef)

# Prerequisites

You should have both `gdb` and `gdbserver` installed on your machine.
You can check this easily with `which gdb` or `which gdbserver`.

If you find that you don't have them installed, they can easily be installed from
most package managers.

```sh
$ sudo apt-get install gdb gdbserver
```

# Launching a Process Under GDB

Launching a process under GDB while still being able to interact with that process
from pwntools is a tricky process, but luckily it's all been sorted out and the 
process is pretty seamless.

To launch a process under GDB from the very first instruction, just use 
[gdb.debug](https://docs.pwntools.com/en/stable/gdb.html#pwnlib.gdb.debug).

```py
>>> io = gdb.debug("/bin/bash", gdbscript='continue')
>>> io.sendline('echo hello')
>>> io.recvline()
# b'hello\n'
>>> io.interactive()
```

This should automatically launch the debugger in a new window for you to interact
with.  If it does not, or you see an error about `context.terminal`, check out the
section on [Specifying a Terminal Window](#specifying-a-terminal-window).

In this example, we passed in `gdbscript='continue'` in order for the debugger
to resume execution, but you can pass in any valid GDB script commands and they
will be executed when the debugged process starts.

# Attaching to a Running Process

Sometimes you don't want to start your target under a debugger, but want to attach
to it at a certain stage in the exploitation process.  
This is also handled seamlessly by Pwntools.

## Local Processes

Generally, you will have created a `process()` tube in order to interact with the
target executable.  You can simply pass that to `gdb.attach()` and it will magically
open a new terminal window with the target binary under the debugger.

```py
>>> io = process('/bin/sh')
>>> gdb.attach(io, gdbscript='continue')
```

A new window should appear, and you can continue to interact with the process
as you normally would from Pwntools.

## Forking Servers

Sometimes the binary you want to debug has a forking server, and you want to
debug the process you are connected to (rather than the server itself).  This
is also done seamlessly, as long as the server is running on the current machine.

Let's fake a server with socat!

```py
>>> socat = process(['socat', 'TCP-LISTEN:4141,reuseaddr,fork', 'EXEC:/bin/bash -i'])
```

Then we connect to the remote process with a `remote` tube as usual.


```py
>>> io = remote('localhost', 4141)
[x] Opening connection to localhost on port 4141
[x] Opening connection to localhost on port 4141: Trying 127.0.0.1
[+] Opening connection to localhost on port 4141: Done
>>> io.sendline('echo hello')
>>> io.recvline()
b'hello\n'
>>> io.lport, io.rport
```

It works!  In order to debug the specific `bash` process our `remote` object, just
pass it to `gdb.attach()`.  Pwntools will look up the PID of the remote end of the 
connection and attempt to connect to it automatically.

```py
>>> gdb.attach(io)
```

A debugger should appear automatically, and you can interact with the process.

<!-- TODO: This is currently broken, see https://github.com/Gallopsled/pwntools/issues/1589 -->

# Debugging Foreign Architectures

Debugging foreign architectures (like ARM or PowerPC) from an Intel-based system is
as easy as running them under pwntools.

```py
>>> context.arch = 'arm'
>>> elf = ELF.from_assembly(shellcraft.echo("Hello, world!\n") + shellcraft.exit())
>>> process(elf.path).recvall()
b'Hello, world!\n'
```

Instead of invoking `process(...)` just use `gdb.debug(...)`.

```py
>>> gdb.debug(elf.path).recvall()
b'Hello, world!\n'
```

## Tips and Limitations

Processes running foreign architectures MUST be started with `gdb.debug` in order
to debug them, it is not possible to attach to a running process due to the way
that QEMU works.

It should be noted that QEMU has a very limited GDB stub, which is used to
inform GDB where various libraries are, so debugging may be more difficult,
and some commands will not work.

Pwntools recommends Pwndbg to handle this situation, since it has code specifically
to handle debugging under a QEMU stub.

<!-- TODO: There is no tutorial for interacting with cross-arch binaries -->

# Troubleshooting

## Behind the Scenes

Sometimes things just don't work, and you need to see what is happening internal
to Pwntools with the debugger setup.

You can set the logging context globally (via e.g. `context.log_level='debug'`)
or you can set it ONLY for the GDB session, via passing in the same argument.

You should see everything that's being handled for you behind the scenes.
For example:

```py
>>> io = gdb.debug('/bin/sh', log_level='debug')
[x] Starting local process '/home/user/bin/gdbserver' argv=[b'/home/user/bin/gdbserver', b'--multi', b'--no-disable-randomization', b'localhost:0', b'/bin/sh']
[+] Starting local process '/home/user/bin/gdbserver' argv=[b'/home/user/bin/gdbserver', b'--multi', b'--no-disable-randomization', b'localhost:0', b'/bin/sh'] : pid 34282
[DEBUG] Received 0x25 bytes:
    b'Process /bin/sh created; pid = 34286\n'
[DEBUG] Received 0x18 bytes:
    b'Listening on port 45145\n'
[DEBUG] Wrote gdb script to '/tmp/user/pwnxcd1zbyx.gdb'
    target remote 127.0.0.1:45145
[*] running in new terminal: /usr/bin/gdb -q  "/bin/sh" -x /tmp/user/pwnxcd1zbyx.gdb
[DEBUG] Launching a new terminal: ['/usr/local/bin/tmux', 'splitw', '/usr/bin/gdb -q  "/bin/sh" -x /tmp/user/pwnxcd1zbyx.gdb']
[DEBUG] Received 0x25 bytes:
    b'Remote debugging from host 127.0.0.1\n'
```


## Specifying a Terminal Window

Pwntools [attempts to launch a new window][run_in_new_terminal] to container your 
debugger based on whatever windowing system you are currently using.  

By default, it auto-detects:

* tmux or screen
* X11-based terminals like GNOME Terminal

If you are not using a supported terminal environment, or it does not work in the
way you want (e.g. horizontal vs vertical splits) you can add support by setting
the `context.terminal` environment variable.

For example, the following will use TMUX to split horizontally instead of the default.

```py
>>> context.terminal = ['tmux', 'splitw', '-h']
```

Maybe you're a GNOME Terminal user and the default settings aren't working?

```py
>>> context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
```

You can specify any terminal you like, and can even put the setting inside
`~/.pwn.conf` so that it's used for all of you scripts!

```
[context]
terminal=['x-terminal-emulator', '-e']
```

## Environment Variables

Pwntools allows you to specify any environment variables you like via `process()`,
and the same is true for `gdb.debug()`.

```py
>>> io = gdb.debug(['bash', '-c', 'echo $HELLO'], env={'HELLO': 'WORLD'})
>>> io.recvline()
b'WORLD\n'
```

### `CWD` and `   `

Unfortunately, when using `gdb.debug()`, the process is launched under `gdbserver`
which adds its own environment variables.  This may introduce complications when
the environment must be very carefully controlled.

```py
>>> io = gdb.debug(['env'], env={'FOO':'BAR'}, gdbscript='continue')
>>> print(io.recvallS())
   =/home/user/bin/gdbserver
FOO=BAR

Child exited with status 0
GDBserver exiting
```

This only occurs when you launch the process under a debugger with `gdb.debug()`.
If you're able to start your process and *then* attach with `gdb.attach()`, you
can avoid this issue.

### Environment Variable Ordering

Some exploits may require that certain environment variables are in a specific
order.  Python2 dictionaries are not ordered, which may exacerbate this issue.

In order to have your environment variables in a specific order, we recommend
using Python3 (which orders dictionaries based on insertion order), or using
`collections.OrderedDict`.

## Unable to Attach to Processes

Modern Linux systems have a setting called `ptrace_scope` which prevents processes
that are not child processes from being debugged.  Pwntools works around this
for any processes that it launches itself, but if you have to launch a process
outside of Pwntools and try to attach to it by pid (e.g. `gdb.attach(1234)`),
you may be prevented from attaching.

You can resolve this by disabling the security setting and rebooting your machine:

```sh
sudo tee /etc/sysctl.d/10-ptrace.conf <<EOF
kernel.yama.ptrace_scope = 0
EOF
```

## argv0 and argc==0

Some challenges require that they are launched with `argv[0]` set to a specific
value, or even that it's NULL (i.e. `argc==0`).

It is not possible to launch a processs with this configuration via `gdb.debug()`,
but you can use `gdb.attach()`.  This is because of limitations of launching
binaries under gdbserver.