#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

int main(void)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;

    obj = bpf_object__open_file("hello.bpf.o", NULL);

    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "hello");

    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    link = bpf_program__attach_tracepoint(
        prog,
        "syscalls",
        "sys_enter_execve"
    );

    if (!link) {
        fprintf(stderr, "Failed to attach tracepoint\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("eBPF program loaded and attached successfully!\n");
    printf("Press Ctrl+C to stop.\n");

    while (1)
        sleep(1);

    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}
