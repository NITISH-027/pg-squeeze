#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct pg_event {
    __u32 pid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 packet_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");


SEC("tc")
int net_observer(struct __sk_buff *skb)
{
    /*
     * ---------------------------------------------------------
     * Only inspect IPv4 packets.
     *
     * skb->protocol tells us the Layer-3 protocol associated
     * with this packet.
     * ---------------------------------------------------------
     */

    if (skb->protocol != bpf_htons(ETH_P_IP))
        return 0;


    /*
     * ---------------------------------------------------------
     * Read the IPv4 header relative to the network header.
     *
     * This avoids assuming that skb->data begins with an
     * Ethernet header.
     *
     * That is important because we monitor both:
     *
     *     eth0
     *     lo
     * ---------------------------------------------------------
     */

    struct iphdr ip = {};

    int ret;

    ret = bpf_skb_load_bytes_relative(
        skb,
        0,
        &ip,
        sizeof(ip),
        BPF_HDR_START_NET
    );

    if (ret < 0)
        return 0;


    /*
     * ---------------------------------------------------------
     * Validate IPv4.
     * ---------------------------------------------------------
     */

    if (ip.version != 4)
        return 0;


    if (ip.protocol != IPPROTO_TCP)
        return 0;


    /*
     * ---------------------------------------------------------
     * Calculate IPv4 header length.
     * ---------------------------------------------------------
     */

    __u32 ip_header_len =
        (__u32)ip.ihl * 4;

    if (ip_header_len < sizeof(struct iphdr))
        return 0;


    /*
     * ---------------------------------------------------------
     * Read TCP header.
     *
     * We start after the IPv4 header.
     * ---------------------------------------------------------
     */

    struct tcphdr tcp = {};

    ret = bpf_skb_load_bytes_relative(
        skb,
        ip_header_len,
        &tcp,
        sizeof(tcp),
        BPF_HDR_START_NET
    );

    if (ret < 0)
        return 0;


    /*
     * ---------------------------------------------------------
     * Extract ports.
     * ---------------------------------------------------------
     */

    __u16 src_port =
        bpf_ntohs(tcp.source);

    __u16 dst_port =
        bpf_ntohs(tcp.dest);


    /*
     * ---------------------------------------------------------
     * PostgreSQL standard TCP port.
     * ---------------------------------------------------------
     */

    if (src_port != 5432 &&
        dst_port != 5432)
        return 0;


    /*
     * ---------------------------------------------------------
     * Reserve ring-buffer event.
     * ---------------------------------------------------------
     */

    struct pg_event *event;

    event = bpf_ringbuf_reserve(
        &events,
        sizeof(*event),
        0
    );

    if (!event)
        return 0;


    /*
     * ---------------------------------------------------------
     * Context PID.
     *
     * IMPORTANT:
     * This is packet-processing context information.
     *
     * It is NOT yet our definitive application PID.
     *
     * Proper socket/process correlation will be implemented
     * later in userspace.
     * ---------------------------------------------------------
     */

    __u64 pid_tgid =
        bpf_get_current_pid_tgid();

    event->pid =
        pid_tgid >> 32;


    /*
     * ---------------------------------------------------------
     * Network information.
     * ---------------------------------------------------------
     */

    event->src_ip =
        ip.saddr;

    event->dst_ip =
        ip.daddr;

    event->src_port =
        src_port;

    event->dst_port =
        dst_port;


    /*
     * ---------------------------------------------------------
     * Packet size.
     * ---------------------------------------------------------
     */

    event->packet_len =
        skb->len;


    /*
     * ---------------------------------------------------------
     * Submit event.
     * ---------------------------------------------------------
     */

    bpf_ringbuf_submit(
        event,
        0
    );

    return 0;
}


char LICENSE[] SEC("license") = "GPL";
