#!/bin/bash
rm -rf bin
mkdir bin
g++ one_weird_syscall.cpp -static -lcap -luring -s -o bin/one_weird_syscall
