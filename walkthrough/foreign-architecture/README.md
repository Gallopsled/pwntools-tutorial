# Foreign Architecture

This example is the exact same as the Basic Buffer Overflow example, but demonstrates how to interact with foreign-architecture binaries.

In order for all of this to work, you'll need some cross-architecture libraries installed.  FOr this example, we'll use ARM as it's easy to get the dependencies on Ubuntu.

Detailed instructions for setting up a foreign-architecture toolchain are available in my [StackExchange post][post].  While the topic is MIPS, the exact same steps apply.

If you just want the commands and no prose, here you go:

```sh
sudo apt-get install qemu qemu-user qemu-user-static
sudo apt-get install gdb-multiarch
sudo apt-get install libc6-armhf-armel-cross
sudo apt-get install gcc-arm-linux-gnueabihf
sudo mkdir /etc/qemu-binfmt
sudo ln -s /usr/arm-linux-gnueabihf /etc/qemu-binfmt/arm
```

[post]: http://reverseengineering.stackexchange.com/a/8917/12503
