# Agent Run Scripts
This directory contains runscripts for the specific container images tested against all bypasses and exploits.
It is important to note that using the "latest" container image for falco or tracee could yield different results
than those presented in "A Compendium of Exploits and Bypasses for eBPF-based Cloud Security" at SANS Hackfest 2023.

The specific version of falco used is falcosecurity/falco-no-driver:0.36.2

The specific version of tracee used is aquasec/tracee:0.19.0

All examples have been tested on an Ubuntu 22.04.1 system with 2 CPUs and 2 GB of RAM, kernel version `5.15.0-50-generic #56-Ubuntu SMP Tue Sep 20 13:23:26 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux`
