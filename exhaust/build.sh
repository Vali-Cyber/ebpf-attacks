#!/bin/bash
rm -rf bin
mkdir bin
g++ exhaust.cpp -static -lstdc++fs --std=c++17 -O3 -o bin/exhaust
