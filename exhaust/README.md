# Exhaust
This directory contains a program that fills eBPF maps with junk data before executing a malicious action.
The malicious action goes undetected because the eBPF map is full, preventing a userspace agent from processing
the event. Depending on the agent's configuration and the amount of RAM on the system, you may need to adjust the
`counter_value` in `exhaust.cpp`

To build: `./build.sh`

The output of the build script is placed in the bin directory.

To run against falco: `./exhaust`

To run against tracee: `./exhaust -tracee`

## Other Resources
[CVE-2019-8339, Falco Resource Consumption](https://nvd.nist.gov/vuln/detail/CVE-2019-8339)

[CVE-2019-8339 Description](https://sysdig.com/blog/cve-2019-8339-falco-vulnerability/)
