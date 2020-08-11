#!/bin/bash

cat header.asm graph.asm program.asm footer.asm > temp.asm
nasm -f bin -o program temp.asm
chmod +x program

