#!/bin/bash
rm -rf bin
mkdir bin
g++ delete_keys.cpp -static -s -lbpf -O3 -o bin/delete_keys
