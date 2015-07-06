#!/bin/sh
nasm smm_call.asm -o smm_call.o -f elf64
gcc main.c smm_call.o -o smm_call
