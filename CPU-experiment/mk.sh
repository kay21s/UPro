#!/bin/bash

yasm="./yasm"

pushd .
asm="iaesx64 do_rdtsc"
for i in $asm; do echo do $i.s; $yasm -D__linux__ -g dwarf2 -f elf64 $i.s -o obj/$i.o; done
gcc -O3 -c intel_aes.c -o obj/intel_aes64.o
ar -r lib/intel_aes64.a obj/*.o
popd

gcc -o cpu_enc cpu_enc.c sha1-fast-64.S lib/intel_aes64.a
