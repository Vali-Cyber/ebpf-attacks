# Some Weird Syscalls...
This directory contains code that compiles into a program and a dynamically linked library.
The `some_weird_syscalls` program executes either the `open_by_handle_at` or the `io_uring_setup`
syscall. The dynamic lib simply uses the `io_uring_setup` syscall.

To build: `./build.sh`

The output of the build script is placed in the bin directory.

To target falco while running on the host OS. Specify the `-uring` command
line flag to use the `io_uring_setup` syscalls. Otherwise, use the `open_by_handle_at` syscall: `./some_weird_syscalls [-uring]`

To target falco while running in a container: `LD_PRELOAD=PATH_TO_some_weird_syscalls.so ls`
