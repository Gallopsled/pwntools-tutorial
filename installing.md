Table of Contents
=================

  * [Installing Pwntools](#installing-pwntools)
    * [Verifying Installation](#verifying-installation)
    * [Foreign Architectures](#foreign-architectures)

# Installing Pwntools

This process is as straightforward as it can be.  Ubuntu 14.04 and 12.04 are the only "officially supported" platforms, in that they're the only platforms we do automated testing on.

```sh
apt-get update
apt-get install python2.7 python-pip python-dev git
pip install --upgrade git+https://github.com/Gallopsled/pwntools.git
```

Everything else, you're on your own.

## Verifying Installation

Everything should be A-OK if the following command succeeds:

```sh
$ python -c 'from pwn import *'
```

## Foreign Architectures

If you want to assemble or disassemble code for foreign architectures, you need an appropriate `binutils` installation.  For Ubuntu and Mac OS X users, the [installation instructions][binutils] are very straightforward.  The pre-built binaries are available from Ubuntu Launchpad.  These are built by Ubuntu, on their servers, using the original unmodified source package -- no need to trust maintainers!

For example, to install `binutils` for MIPS:

```sh
$ apt-get install software-properties-common
$ apt-add-repository ppa:pwntools/binutils
$ apt-get update
$ apt-get install binutils-mips-linux-gnu
```

[binutils]: https://pwntools.readthedocs.org/en/latest/install/binutils.html
