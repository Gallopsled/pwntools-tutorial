# Installing Binjitsu

This process is as straightforward as it can be.  Ubuntu 14.04 and 12.04 are the only "officially supported" platforms, in that they're the only platforms we do automated testing on.

```sh
apt-get update
apt-get install python2.7 python-pip python-dev git
pip install --upgrade git+https://github.com/binjitsu/binjitsu.git
```

Everything else, you're on your own.

## Verifying Installation

Everything should be A-OK if the following command succeeds:

```sh
$ python -c 'from pwn import *'
```