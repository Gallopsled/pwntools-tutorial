Table of Contents
=================

  * [Installing Pwntools](#installing-pwntools)
    * [Verifying Installation](#verifying-installation)
    * [Foreign Architectures](#foreign-architectures)

# Installing Pwntools

This process is as straightforward as it can be.  Ubuntu 18.04 and 20.04 are the only "officially supported" platforms, in that they're the only platforms we do automated testing on.

```sh
$ apt-get update
$ apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
$ python3 -m pip install --upgrade pip
$ python3 -m pip install --upgrade pwntools
```

## Verifying Installation

Everything should be A-OK if the following command succeeds:

```sh
$ python -c 'from pwn import *'
```

## Foreign Architectures

If you want to assemble or disassemble code for foreign architectures, you need an appropriate `binutils` installation.  For Ubuntu and Mac OS X users, the [installation instructions][binutils] are available on docs.pwntools.com.

```sh
$ apt-get install binutils-*
```

[binutils]: https://pwntools.readthedocs.org/en/latest/install/binutils.html
