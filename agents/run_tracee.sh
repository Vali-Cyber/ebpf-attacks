#!/bin/bash
docker run --name tracee --rm -it --pid=host --cgroupns=host --privileged -v /etc/os-release:/etc/os-release-host:ro -v /boot:/boot:ro aquasec/tracee:0.19.0
