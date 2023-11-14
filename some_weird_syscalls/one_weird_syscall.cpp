#include <iostream>

#include <fcntl.h>
#include <liburing.h>
#include <sys/capability.h>
#include <unistd.h>

constexpr char falco_file[] = "/etc/pam.conf";

bool has_capability(int capability) {
    cap_t caps = cap_get_proc();
    cap_flag_value_t value;

    if (cap_get_flag(caps, capability, CAP_EFFECTIVE, &value) < 0) {
        std::cerr << "Error getting capabilities" << std::endl;
        cap_free(caps);
        return false;
    }

    cap_free(caps);

    return (value == CAP_SET);
}

void write_out_file(int fd) {
    char buffer[4096] = {};
    int bytesRead = read(fd, buffer, sizeof(buffer)-1);
    if (bytesRead < 0) {
        std::cerr << "Error reading from file" << std::endl;
    } else {
        // Print the data to stdout
        write(STDOUT_FILENO, buffer, bytesRead);
    }
}

void open_file_handle_at(const char *file_path){
        if (has_capability(CAP_DAC_READ_SEARCH)) {
            struct file_handle *fhp;
            int mount_id, fhsize, flags, dirfd, j, x;
            ssize_t nread;
            x = 0;
            int a = 0;
            fhsize = sizeof(*fhp);
            fhp = (file_handle*)malloc(fhsize);
            if (fhp == NULL)
               exit(EXIT_FAILURE);
            dirfd = AT_FDCWD;
            flags = 0;                  /* For name_to_handle_at() calls */
            fhp->handle_bytes = 0;

            if (name_to_handle_at(dirfd, file_path, fhp, &mount_id, flags) != -1 || errno != EOVERFLOW){
                std::cerr << "name_to_handle_at failed, exiting" << std::endl;
                exit(1);
            }

            fhsize = sizeof(struct file_handle) + fhp->handle_bytes;
               fhp = (file_handle*) realloc(fhp, fhsize);         /* Copies fhp->handle_bytes */
               if (fhp == NULL) {
                  exit(1);
               }
            if (name_to_handle_at(dirfd, file_path, fhp, &mount_id, flags) == -1)
                   std::cerr << "bad name_to_handle!!!" << std::endl;
            a = open_by_handle_at(dirfd, fhp, O_RDONLY);
            write_out_file(a);
        } else {
            std::cerr << "This command does not have the CAP_DAC_READ_SEARCH capability. Try running it as root." << std::endl;
            exit(1);
        }
}

void open_file_iouring(const char *file_path) {
    struct io_uring ring;

    // Initialize io_uring
    io_uring_queue_init(16, &ring, 0);

    // Prepare open request
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);

    // Set up the openat operation
    io_uring_prep_openat(sqe, AT_FDCWD, file_path, O_RDONLY, 0);

    // Submit request
    io_uring_submit(&ring);

    // Wait for completion
    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(&ring, &cqe);

    if (cqe->res < 0) {
        std::cerr << "Error opening file" << std::endl;
    } else {
        std::cout << "File opened successfully" << std::endl;
        // Read data from the file
        int fd = cqe->res;
        write_out_file(fd);
    }

    // Clean up
    io_uring_cq_advance(&ring, 1);
    io_uring_queue_exit(&ring);

}

void printUsageMessage() {
    std::cout << "Usage: ./one_weird_syscall [-uring]" << std::endl;
    std::cout << "    -uring: Use io_uring syscalls. The default configuration uses open by handle at." << std::endl;
}

void parseArgs(int argc, char* argv[], bool *is_uring) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-uring") {
            *is_uring = true;
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            printUsageMessage();
            exit(1);
        }
    }
}



int main(int argc, char *argv[]) {
    bool is_uring = false;
    parseArgs(argc, argv, &is_uring);
    std::cout << "Tring to read \"" << falco_file << "\"..." <<  std::endl;
    if (is_uring) {
        open_file_iouring(falco_file);
    } else {
        open_file_handle_at(falco_file);
    }

    return 0;
}


