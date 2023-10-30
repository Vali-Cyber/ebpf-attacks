#!/bin/bash
rm -rf bin
mkdir bin
g++ delete_keys.cpp -lbpf -lstdc++fs --std=c++17 -O3 -o bin/delete_keys
