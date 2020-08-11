#!/bin/sh

yes | sudo dpkg --add-architecture i386
yes | sudo apt update
yes | sudo apt install libc6:i386 libncurses5:i386 libstdc++6:i386 binutils gdb
