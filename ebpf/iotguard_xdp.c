// IoTGuard In-Kernel Wire-Speed Packet Filter (eBPF / XDP)
// Implements Future-Proofing eBPF Migration Blueprint:
// Drops malicious packets directly in the network driver before OS kernel stack allocation.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Definition of IP pair for Level 2 Destination Blocking (device_ip . dest_ip)
struct ip_pair {
    __u32 saddr;
    __u32 daddr;
};

// BPF Map for Level 3: Quarantined Device IPs (All Forwarded Packets Dropped)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);     // IPv4 source address
    __type(value, __u64);   // Dropped packet counter
} quarantined_dev_map SEC(".maps");

// BPF Map for Level 2: Blocked Destination Pairs (Device to C2/Payload)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ip_pair); // (saddr, daddr)
    __type(value, __u64);        // Dropped packet counter
} blocked_dst_map SEC(".maps");

SEC("xdp")
int iotguard_xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // 2. Parse IPv4 Header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;

    // 3. Level 3 Quarantine Check: Is originating device quarantined?
    __u64 *q_count = bpf_map_lookup_elem(&quarantined_dev_map, &src_ip);
    if (q_count) {
        __sync_fetch_and_add(q_count, 1);
        return XDP_DROP; // Wire-speed drop in NIC/driver
    }

    // 4. Level 2 Destination Check: Is specific destination host blocked?
    struct ip_pair pair = {
        .saddr = src_ip,
        .daddr = dst_ip
    };

    __u64 *b_count = bpf_map_lookup_elem(&blocked_dst_map, &pair);
    if (b_count) {
        __sync_fetch_and_add(b_count, 1);
        return XDP_DROP; // Wire-speed drop in NIC/driver
    }

    // 5. Normal traffic: Pass to kernel network stack & Zeek sensor
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
