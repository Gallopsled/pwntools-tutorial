# Advanced Shellcode

**Note**: You should check out the [basic](../shellcode-basic/README.md) and [intermediate](../shellcode-intermediate/README.md) tutorial first!

In order to build new modules and make them available via `shellcraft`, only a few steps are necessary.

First, all of the `shellcraft` templates are really just [Mako][mako] templates.  Generally this is used for server-side scripting in Python web servers, but it fits the application of pasting together arbitrary bits of shellcode very well!

The templates are all located in the `pwnlib/shellcraft/templates/ARCH/OS` directories.  For example `$ shellcraft i386.linux.sh` is actually invoking the template defined in [`pwnlib/shellcraft/templates/i386/linux/sh.asm`][sh]

## Syntax Highlighting

This generally helps make the templates more readable.  Pwntools has a [syntax highlighting](https://github.com/Gallopsled/pwntools/blob/master/extra/textmate/README.md) plug-in for Sublime Text / TextMate.

## Anatomy of a Simple Template

For Pwntools, the general format of a template looks like what's shown below.
In particular, there are a few things to note about syntax:

- `<%` and `%>` contain Python code blocks
- `<%tag>` and `</%tag>` contain special tags defined by Pwntools or Mako
    + These are used to generate the function wrappers
- `${...}` is a Python expression
    - `${var}` is replaced with the Python variable (as passed through `str()` or `%s`)
    - `${function(...)}` is the same, the return value is inserted in its place
        + Mako templates just emit a string, this makes it very easy to nest them!
- Lines starting with `##` are ignored by Mako
- Everything else is emitted verbatim.

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
<%
# The constants module lets the user provide the string 'SYS_execve',
# and then we can resolve it to the integer value.
#
# For example, on i386, constants.eval('SYS_execve') == 11
from pwnlib import constants

# Pushstr provides a simple way to get a string onto the stack
# with no NULLs or newlines in the emitted assembly.
from pwnlib.shellcraft.i386 import pushstr

# Mov provides a simple way to mov values into registers, or
# between registers, without caring which is occurring.
# It also is generally NULL- and newline-free.
#
# This is not a big deal on i386 since it's all the same instruction,
# but on RISC architectures it's really a requirement.
from pwnlib.shellcraft.i386 import mov

# All of the Linux syscalls have a small wrapper template around them.
# These are in turn a wrapper around the "syscall" template.
# The syscall template is in turn as wrapper around the "mov" template
# to move the values into the appropriate registers.
#
# Using the "write" syscall wrapper is much more convenient than writing
# everything out by hand, even if some of the code is duplicated.
from pwnlib.shellcraft.i386.linux import write

# The label template provides a way to ensure that all labels are unique.
# This is important if the same shellcode is included multiple times,
# which is common for simple loops.
from pwnlib.shellcraft.common import label
%>

## The arguments section allows us to specify arguments to the template.
## These are turned into Python arguments for the Python function wrapper.
<%page args="sock, message, spin=False"/>

## The docstring is useful and informative for users, but is not required.
## This is printed out with "shellcraft ... -?".
<%docstring>
Sends a message to a file descriptor, and then loops forever!

Arguments:
    sock(int,reg): Socket to send the message over
    message(str): Message to send
    spin(bool): Infinite loop after sending the message

</%docstring>

## Templates can embed Python logic directly.
## Any variables or functions created in a block are available
## immediately in the template.
<%
    target = label('target')

    # This is not necessary since we're just passing it into
    # the 'mov' template, which already does this.
    # Just for demonstration purposes.
    sock = constants.eval(sock)
%>

## Other templates are inserted as a Python function call.
    /* Push the message onto the stack */
    ${pushstr(message)}

    /* Set the socket into edi for fun */
    ${mov('edi', sock)}

    /* Invoke the write syscall */
    ${write('edi', 'esp', len(message))}

## Templates can include conditional logic, to either include
## or exclude certain sections.
%if spin:
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

## "Reserved words declared in template"

You can't have any variables named `loop`, among some other things.  It's a limitation of Mako.

## Template Caching

One problem you may run into is Mako template caching.  In order to make Pwntools as speedy as possible, the compiled templates are cached.  This is sometimes a burden on development of new shellcode, but in general is useful.

If you run into weird problems, try clearing the cache in `~/.pwntools-cache/mako` (or `~/.pwntools-cache/mako`).

[mako]: http://makotemplates.org
[sh]: https://github.com/Gallopsled/pwntools/blob/master/pwnlib/shellcraft/templates/i386/linux/sh.asm
