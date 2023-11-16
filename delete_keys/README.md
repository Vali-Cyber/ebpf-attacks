# Exhaust
This directory contains a program that finds and deletes all the keys from eBPF maps depending on the
target application.

To build: `./build.sh`

The output of the build script is placed in the bin directory.

To run against falco: `./delete_keys -falco`

To run against tracee: `./delete_keys -tracee`
