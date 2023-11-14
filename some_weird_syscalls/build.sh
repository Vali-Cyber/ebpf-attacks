#!/bin/bash
rm -rf bin
mkdir bin
g++ some_weird_syscalls.cpp -static -lcap -luring -s -o bin/some_weird_syscalls
gcc some_weird_syscalls.c -shared -luring -s -fPIC -o bin/some_weird_syscalls.so
