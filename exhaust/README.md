# Exhaust
This directory contains a program that fills eBPF maps with junk data before execution a malicious action.
The malicious action goes undetected because the eBPF map is full, preventing a userspace agent from processing
the event. Depending on agent's configuration and the amount of RAM on the system, you may need to adjust the
`counter_value` in `exhaust.cpp`

To build: `./build.sh`

The output of the build script is placed in the bin directory.

To run against falco: `./exhaust`

To run against tracee: `./exhaust -tracee`
