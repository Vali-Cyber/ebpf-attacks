#!/bin/bash
docker run --rm -i -t --cap-drop all --cap-add sys_admin --cap-add sys_resource --cap-add sys_ptrace -v /var/run/docker.sock:/host/var/run/docker.sock -v /proc:/host/proc:ro falcosecurity/falco-no-driver:0.36.2 falco --modern-bpf
