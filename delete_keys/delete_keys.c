#include <stdio.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>

#define BPF_OBJ_NAME_LEN 16U

const size_t attr_sz = sizeof(union bpf_attr);
const __u32 info_len = sizeof(struct bpf_map_info);

struct bpf_get_fd_by_id_opts {
    size_t sz; /* size of this struct for forward/backward compatibility */
    __u32 open_flags; /* permissions requested for the operation on fd */
    size_t :0;
};

int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size) {
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

int main(int argc, char *argv[]) {

    int id = 0;
        printf("YO\n");
        
            //void *key = malloc(info.key_size);
            //while (bpf_map_get_next_key(fd, NULL, key) == 0) {
                __u32 key = 0;

                while (key < 8196*2+3000-1300-22) {
                    FILE *f2 = fopen("/proc/1/status", "r");
                    fclose(f2);
                    key++;
                }
                FILE *file = fopen("/proc/sys/kernel/randomize_va_space", "r");
                //FILE *file = fopen("/etc/pam.conf", "r");
                char buffer[1024];
                while (fgets(buffer, sizeof(buffer), file) != NULL) {
                    printf("%s", buffer);
                }
                fclose(file);
            //}
            //free(key);
            return 0;
}

