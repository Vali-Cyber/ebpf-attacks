#include <fcntl.h>
#include <liburing.h>
#include <stdio.h>
#include <sys/capability.h>
#include <unistd.h>

char falco_file[] = "/etc/pam.conf";

void write_out_file(int fd) {
    char buffer[4096] = {};
    int bytesRead = read(fd, buffer, sizeof(buffer)-1);
    if (bytesRead < 0) {
        fprintf(stderr, "Error reading from file\n");
    } else {
        // Print the data to stdout
        write(STDOUT_FILENO, buffer, bytesRead);
    }
}

void __attribute__((constructor)) open_file_iouring() {
    struct io_uring ring;

    // Initialize io_uring
    io_uring_queue_init(16, &ring, 0);

    // Prepare open request
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);

    // Set up the openat operation
    io_uring_prep_openat(sqe, AT_FDCWD, falco_file, O_RDONLY, 0);

    // Submit request
    io_uring_submit(&ring);

    // Wait for completion
    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(&ring, &cqe);

    if (cqe->res < 0) {
        fprintf(stderr, "Error opening file\n");
    } else {
        printf("File opened successfully\n");
        // Read data from the file
        int fd = cqe->res;
        write_out_file(fd);
    }

    // Clean up
    io_uring_cq_advance(&ring, 1);
    io_uring_queue_exit(&ring);

}
