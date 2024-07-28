// Hooks
int syscall__probe_entry_accept(struct pt_regs* ctx, int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    uint64_t id = bpf_get_current_pid_tgid();

    // Keep the addr in a map to use during the exit method.
    struct accept_args_t accept_args = {};
    accept_args.addr = (struct sockaddr_in *)addr;
    active_accept_args_map.update(&id, &accept_args);

    return 0;
}

int syscall__probe_ret_accept(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    // Pulling the addr from the map.
    struct accept_args_t* accept_args = active_accept_args_map.lookup(&id);
    if (accept_args != NULL) {
        process_syscall_accept(ctx, id, accept_args);
    }

    active_accept_args_map.delete(&id);
    return 0;
}


// Hooking the entry of accept4
// the signature of the syscall is int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int syscall__probe_entry_accept4(struct pt_regs* ctx, int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    // Getting a unique ID for the relevant thread in the relevant pid.
    // That way we can link different calls from the same thread.
    uint64_t id = bpf_get_current_pid_tgid();

    // Keep the addr in a map to use during the accpet4 exit hook.
    struct accept_args_t accept_args = {};
    accept_args.addr = (struct sockaddr_in *)addr;
    active_accept_args_map.update(&id, &accept_args);

    return 0;
}

// Hooking the exit of accept4
int syscall__probe_ret_accept4(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    // Pulling the addr from the map.
    struct accept_args_t* accept_args = active_accept_args_map.lookup(&id);
    // If the id exist in the map, we will get a non empty pointer that holds
    // the input address argument from the entry of the syscall.
    if (accept_args != NULL) {
        process_syscall_accept(ctx, id, accept_args);
    }

    // Anyway, in the end clean the map.
    active_accept_args_map.delete(&id);
    return 0;
}

// original signature: ssize_t write(int fd, const void *buf, size_t count);
int syscall__probe_entry_write(struct pt_regs* ctx, int fd, char* buf, size_t count) {
    uint64_t id = bpf_get_current_pid_tgid();

    struct data_args_t write_args = {};
    write_args.fd = fd;
    write_args.buf = buf;
    active_write_args_map.update(&id, &write_args);

    return 0;
}

int syscall__probe_ret_write(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = PT_REGS_RC(ctx); // Also stands for return code.

    // Unstash arguments, and process syscall.
    struct data_args_t* write_args = active_write_args_map.lookup(&id);
    if (write_args != NULL) {
        process_data(ctx, id, kEgress, write_args, bytes_count);
    }

    active_write_args_map.delete(&id);
    return 0;
}

// original signature: ssize_t read(int fd, void *buf, size_t count);
int syscall__probe_entry_read(struct pt_regs* ctx, int fd, char* buf, size_t count) {
    uint64_t id = bpf_get_current_pid_tgid();

    // Stash arguments.
    struct data_args_t read_args = {};
    read_args.fd = fd;
    read_args.buf = buf;
    active_read_args_map.update(&id, &read_args);

    return 0;
}

int syscall__probe_ret_read(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    // The return code the syscall is the number of bytes read as well.
    ssize_t bytes_count = PT_REGS_RC(ctx);
    struct data_args_t* read_args = active_read_args_map.lookup(&id);
    if (read_args != NULL) {
        // kIngress is an enum value that let's the process_data function
        // to know whether the input buffer is incoming or outgoing.
        process_data(ctx, id, kIngress, read_args, bytes_count);
    }

    active_read_args_map.delete(&id);
    return 0;
}
// original signature: int close(int fd)
int syscall__probe_entry_close(struct pt_regs* ctx, int fd) {
    uint64_t id = bpf_get_current_pid_tgid();
    struct close_args_t close_args;
    close_args.fd = fd;
    active_close_args_map.update(&id, &close_args);

    return 0;
}

int syscall__probe_ret_close(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    const struct close_args_t* close_args = active_close_args_map.lookup(&id);
    if (close_args != NULL) {
        process_syscall_close(ctx, id, close_args);
    }

    active_close_args_map.delete(&id);
    return 0;
}
