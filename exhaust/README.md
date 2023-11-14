# Exhaust
This directory contains a simple program that fills eBPF maps with junk data before execution a malicious action.
The malicious action goes undetected because the eBPF map is full, preventing a userspace agent from processing
the event.

To build: `./build.sh`

The output of the build script is placed in the bin directory.

To run against falco: `./exhaust`

To run against tracee: `./exhaust -tracee`
