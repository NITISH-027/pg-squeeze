#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <bpf/libbpf.h>

#define NUM_INTERFACES 2

struct tc_attachment {
    const char *ifname;
    int ifindex;

    struct bpf_tc_hook ingress_hook;
    struct bpf_tc_opts ingress_opts;

    struct bpf_tc_hook egress_hook;
    struct bpf_tc_opts egress_opts;

    int ingress_attached;
    int egress_attached;
};

static volatile sig_atomic_t running = 1;

static void handle_signal(int sig)
{
    running = 0;
}

static int attach_interface(
    struct tc_attachment *att,
    struct bpf_program *prog
)
{
    int err;

    att->ifindex = if_nametoindex(att->ifname);

    if (!att->ifindex) {
        fprintf(
            stderr,
            "Failed to find interface %s\n",
            att->ifname
        );

        return -1;
    }

    printf(
        "Using interface %s (ifindex=%d)\n",
        att->ifname,
        att->ifindex
    );

    /*
     * ---------------------------------------------------------
     * INGRESS
     * ---------------------------------------------------------
     */

    att->ingress_hook = (struct bpf_tc_hook){};
    att->ingress_opts = (struct bpf_tc_opts){};

    att->ingress_hook.sz = sizeof(att->ingress_hook);
    att->ingress_hook.ifindex = att->ifindex;
    att->ingress_hook.attach_point = BPF_TC_INGRESS;

    err = bpf_tc_hook_create(&att->ingress_hook);

    if (err && err != -EEXIST) {

        fprintf(
            stderr,
            "[%s] Failed to create ingress hook: %d\n",
            att->ifname,
            err
        );

        return -1;
    }

    att->ingress_opts.sz = sizeof(att->ingress_opts);
    att->ingress_opts.prog_fd =
        bpf_program__fd(prog);
    att->ingress_opts.handle = 1;
    att->ingress_opts.priority = 1;

    err = bpf_tc_attach(
        &att->ingress_hook,
        &att->ingress_opts
    );

    if (err) {

        fprintf(
            stderr,
            "[%s] Failed to attach ingress: %d\n",
            att->ifname,
            err
        );

        bpf_tc_hook_destroy(
            &att->ingress_hook
        );

        return -1;
    }

    att->ingress_attached = 1;

    /*
     * ---------------------------------------------------------
     * EGRESS
     * ---------------------------------------------------------
     */

    att->egress_hook = (struct bpf_tc_hook){};
    att->egress_opts = (struct bpf_tc_opts){};

    att->egress_hook.sz = sizeof(att->egress_hook);
    att->egress_hook.ifindex = att->ifindex;
    att->egress_hook.attach_point = BPF_TC_EGRESS;

    err = bpf_tc_hook_create(&att->egress_hook);

    if (err && err != -EEXIST) {

        fprintf(
            stderr,
            "[%s] Failed to create egress hook: %d\n",
            att->ifname,
            err
        );

        bpf_tc_detach(
            &att->ingress_hook,
            &att->ingress_opts
        );

        att->ingress_attached = 0;

        bpf_tc_hook_destroy(
            &att->ingress_hook
        );

        return -1;
    }

    att->egress_opts.sz = sizeof(att->egress_opts);
    att->egress_opts.prog_fd =
        bpf_program__fd(prog);
    att->egress_opts.handle = 1;
    att->egress_opts.priority = 1;

    err = bpf_tc_attach(
        &att->egress_hook,
        &att->egress_opts
    );

    if (err) {

        fprintf(
            stderr,
            "[%s] Failed to attach egress: %d\n",
            att->ifname,
            err
        );

        bpf_tc_detach(
            &att->ingress_hook,
            &att->ingress_opts
        );

        att->ingress_attached = 0;

        bpf_tc_hook_destroy(
            &att->ingress_hook
        );

        bpf_tc_hook_destroy(
            &att->egress_hook
        );

        return -1;
    }

    att->egress_attached = 1;

    printf(
        "[%s] net_observer attached to ingress + egress.\n",
        att->ifname
    );

    return 0;
}

static void detach_interface(
    struct tc_attachment *att
)
{
    if (att->ingress_attached) {

        bpf_tc_detach(
            &att->ingress_hook,
            &att->ingress_opts
        );

        att->ingress_attached = 0;
    }

    if (att->egress_attached) {

        bpf_tc_detach(
            &att->egress_hook,
            &att->egress_opts
        );

        att->egress_attached = 0;
    }

    /*
     * Destroy only the hooks we created/used.
     * If the kernel reports that the hook cannot be
     * destroyed, we simply continue shutting down.
     */

    bpf_tc_hook_destroy(
        &att->ingress_hook
    );

    bpf_tc_hook_destroy(
        &att->egress_hook
    );
}

int main(void)
{
    const char *obj_file = "net.bpf.o";

    struct tc_attachment attachments[NUM_INTERFACES] = {
        {
            .ifname = "eth0"
        },
        {
            .ifname = "lo"
        }
    };

    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;

    int attached_count = 0;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /*
     * ---------------------------------------------------------
     * OPEN BPF OBJECT
     * ---------------------------------------------------------
     */

    obj = bpf_object__open_file(
        obj_file,
        NULL
    );

    if (!obj) {

        fprintf(
            stderr,
            "Failed to open %s\n",
            obj_file
        );

        return 1;
    }

    /*
     * ---------------------------------------------------------
     * LOAD BPF OBJECT
     * ---------------------------------------------------------
     */

    err = bpf_object__load(obj);

    if (err) {

        fprintf(
            stderr,
            "Failed to load BPF object: %d\n",
            err
        );

        bpf_object__close(obj);

        return 1;
    }

    /*
     * ---------------------------------------------------------
     * FIND PROGRAM
     * ---------------------------------------------------------
     */

    prog = bpf_object__find_program_by_name(
        obj,
        "net_observer"
    );

    if (!prog) {

        fprintf(
            stderr,
            "Failed to find net_observer\n"
        );

        bpf_object__close(obj);

        return 1;
    }

    /*
     * ---------------------------------------------------------
     * ATTACH TO BOTH INTERFACES
     * ---------------------------------------------------------
     */

    for (int i = 0; i < NUM_INTERFACES; i++) {

        if (attach_interface(
                &attachments[i],
                prog
            ) != 0)
        {
            fprintf(
                stderr,
                "Failed to attach to %s\n",
                attachments[i].ifname
            );

            /*
             * Clean up anything that was already attached.
             */
            for (int j = 0; j < i; j++)
                detach_interface(&attachments[j]);

            bpf_object__close(obj);

            return 1;
        }

        attached_count++;
    }

    /*
     * ---------------------------------------------------------
     * RUN
     * ---------------------------------------------------------
     */

    printf("\n");
    printf(
        "PG-SQUEEZE TC loader started.\n"
    );

    printf(
        "Attached net_observer to:\n"
    );

    printf(
        "  eth0 ingress + egress\n"
    );

    printf(
        "  lo   ingress + egress\n"
    );

    printf(
        "Press Ctrl+C to stop.\n"
    );

    while (running)
        sleep(1);

    /*
     * ---------------------------------------------------------
     * CLEANUP
     * ---------------------------------------------------------
     */

    printf(
        "\nStopping PG-SQUEEZE TC loader...\n"
    );

    for (int i = 0; i < attached_count; i++)
        detach_interface(&attachments[i]);

    bpf_object__close(obj);

    printf(
        "PG-SQUEEZE TC loader stopped.\n"
    );

    return 0;
}
