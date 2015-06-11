# Advanced Shellcode

**Note**: You should check out the [basic](../shellcode-basic/README.md) and [intermediate](../shellcode-intermediate/README.md) tutorial first!

In order to build new modules and make them available via `shellcraft`, only a few steps are necessary.

First, all of the `shellcraft` templates are really just [Mako][mako] templates.  Generally this is used for server-side scripting in Python web servers, but it fits the application of pasting together arbitrary bits of shellcode very well!

The templates are all located in the `pwnlib/shellcraft/templates/ARCH/OS` directories.  For example `$ shellcraft i386.linux.sh` is actually invoking the template defined in [`pwnlib/shellcraft/templates/i386/linux/sh.asm`][sh]

## Anatomy of a Simple Template

For Pwntools, the general format of a template looks like what's shown below.
In particular, there are a few things to note about syntax:

- `<%` and `>%` contain Python code blocks
- `<%tag` and `/%tag>` contain special tags defined by Pwntools or Mako
    + These are used to generate the function wrappers
- Python-style (`#`) comments are not emitted

After copying the below template to `pwnlib/shellcraft/templates/i386/linux/demo.asm`, it can be invoked from Python or the command-line tool.

```sh
$ shellcraft i386.linux.demo 1 hello 1
6a6f6868656c6c6a015f89fb89e16a055a6a0458cd80ebfe
$ shellcraft i386.linux.demo 1 hello 1 -f asm | head -n3
    /* Push the message onto the stack */
    /* push 'hello\x00' */
    push 0x6f
...
```

### Sample Template

```
<% from pwnlib import constants %>
<% from pwnlib.shellcraft.i386 import pushstr, mov %>
<% from pwnlib.shellcraft.i386.linux import write %>
<% from pwnlib.shellcraft import common %>
<%page args="sock, message, loop=False"/>
<%docstring>
Sends a message to a file descriptor, and then loops forever!

Arguments:
    sock(int,reg): Socket to send the message over
    message(str): Message to send
    loop(bool): Infinite loop after sending the message

</%docstring>
<%
    target = common.label('target')

    # This is not necessary since we're just passing it into
    # the 'mov' template, which already does this.  Just for
    # demonstration purposes.
    sock = constants.eval(sock)
%>

    /* Push the message onto the stack */
    ${pushstr(message)}

    /* Set the socket into edi for fun */
    ${mov('edi', sock)}

    /* Invoke the write syscall */
    ${write('edi', 'esp', len(message))}

%if loop:
    /* Loop forever */
${target}:
    jmp ${target}
%endif
```

## Tips and Best Practices

And a few things to note about general "good style" for templates.

- Use `common.label` instead of a constant label is preferred, since `common.label` ensures the label name is unique, even if the shellcode template is used multiple times.
- Use the helper functions `mov`, `pushstr`, `syscall`, and the `syscall` wrappers (like `write` used below) instead of reinventing the wheel
    + On some architectures, these emit NULL- and newline-free shellcode
    + These themselves are just other shellcode templates with some logic
- Any integer fields should be passed through `constants.eval` so that well-known constant values can be used instead.
    + `constants.eval("SYS_execve") ==> int`
    + `int(constants.SYS_execve) ==> int`
    + If you're just passing it to another template, e.g. `mov`, this is already handled for you.

# FAQ and Common Problems

## "Reserved wodrs declared in template"

You can't have any variables named `loop`, among some other things.  It's a limitation of Mako.

## Template Caching

One problem you may run into is Mako template caching.  In order to make Pwntools as speedy as possible, the compiled templates are cached.  This is sometimes a burden on development of new shellcode, but in general is useful.

If you run into weird problems, try clearing the cache in `~/.binjitsu-cache/mako` (or `~/.pwntools-cache/mako`).

[sh]: https://github.com/binjitsu/binjitsu/blob/master/pwnlib/shellcraft/templates/i386/linux/sh.asm