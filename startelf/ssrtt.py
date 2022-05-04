#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# ssrtt: based on tcprtt (see below); collect tcp rtt samples during
# slow start phase only, dump to a csv.  samples are in microseconds;
# timestamps are nanosecond-scale, relative to start of CPU.
#
# tcprtt    Summarize TCP RTT as a histogram. For Linux, uses BCC, eBPF.
#
# USAGE: tcprtt [-h] [-T] [-D] [-m] [-i INTERVAL] [-d DURATION]
#           [-p LPORT] [-P RPORT] [-a LADDR] [-A RADDR] [-b] [-B] [-e]
#           [-4 | -6]
#
# Copyright (c) 2020 zhenwei pi
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 23-AUG-2020  zhenwei pi  Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
from socket import inet_ntop, AF_INET
import socket, struct
import argparse
import ctypes
import csv

# arguments
examples = """examples:
    ./tcprtt            # summarize TCP RTT
    ./tcprtt -p         # filter for local port
    ./tcprtt -P         # filter for remote port
    ./tcprtt -a         # filter for local address
    ./tcprtt -A         # filter for remote address
    ./tcprtt -b         # show sockets histogram by local address
    ./tcprtt -B         # show sockets histogram by remote address
    ./tcprtt -D         # show debug bpf text
    ./tcprtt -4         # trace only IPv4 family
    ./tcprtt -6         # trace only IPv6 family
"""
parser = argparse.ArgumentParser(
    description="Collect TCP RTT during slow start",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-i", "--interval",
    help="summary interval, seconds")
parser.add_argument("-d", "--duration", type=int, default=99999,
    help="total duration of trace, seconds")
parser.add_argument("-p", "--lport",
    help="filter for local port")
parser.add_argument("-P", "--rport",
    help="filter for remote port")
parser.add_argument("-a", "--laddr",
    help="filter for local address")
parser.add_argument("-A", "--raddr",
    help="filter for remote address")
parser.add_argument("-b", "--byladdr", action="store_true",
    help="show sockets histogram by local address")
parser.add_argument("-B", "--byraddr", action="store_true",
    help="show sockets histogram by remote address")
parser.add_argument("-D", "--debug", action="store_true",
    help="print BPF program before starting (for debugging purposes)")
parser.add_argument("-o", "--output", default="sslatency.csv",
    help="Output file name for ss latency samples")
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true",
    help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true",
    help="trace IPv6 family only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
if not args.interval:
    args.interval = args.duration

# define BPF program
bpf_text = """
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "bcc"
#endif
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

typedef struct sock_key {
    u64 addr;
    u64 slot;
} sock_key_t;

typedef struct sock_latenty {
    u64 latency;
    u64 count;
} sock_latency_t;

#define MAXRESULTS  65536
struct latency_sample {
    u64         timestamp;
    u64         rtt;
};

BPF_HASH(latency, u64, sock_latency_t);
BPF_ARRAY(results, struct latency_sample, MAXRESULTS); // key: index 0 in resultstate
BPF_ARRAY(resultstate, int, 2); // 0: index to results; 1: congstate

#define CONG_STATE_UNKNOWN 0
#define CONG_STATE_SS 1
#define CONG_STATE_CA 2

int kprobe__tcp_slow_start(struct pt_regs *ctx, struct sock *sk) {
    struct tcp_sock *ts = tcp_sk(sk);
    const struct inet_sock *inet = inet_sk(sk);

    /* filters */
    u16 sport = 0;
    u16 dport = 0;
    u32 saddr = 0;
    u32 daddr = 0;
    u16 family = 0;

    /* for avg latency, if no saddr/daddr specified, use 0(addr) as key */
    u64 addr = 0;

    bpf_probe_read_kernel(&sport, sizeof(sport), (void *)&inet->inet_sport);
    bpf_probe_read_kernel(&dport, sizeof(dport), (void *)&inet->inet_dport);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), (void *)&inet->inet_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), (void *)&inet->inet_daddr);
    bpf_probe_read_kernel(&family, sizeof(family), (void *)&sk->__sk_common.skc_family);

    LPORTFILTER
    RPORTFILTER
    LADDRFILTER
    RADDRFILTER
    FAMILYFILTER

    int one = 1;
    int *stateidx = resultstate.lookup(&one);
    if (stateidx == NULL) {
        return -1;
    }
    if (*stateidx != CONG_STATE_SS) {
        bpf_trace_printk("Switching to SS %ull", bpf_ktime_get_ns());
    }
    *stateidx = CONG_STATE_SS;
    return 0;
}

int kprobe__tcp_cong_avoid_ai(struct pt_regs *ctx, struct sock *sk) {
    struct tcp_sock *ts = tcp_sk(sk);
    const struct inet_sock *inet = inet_sk(sk);

    /* filters */
    u16 sport = 0;
    u16 dport = 0;
    u32 saddr = 0;
    u32 daddr = 0;
    u16 family = 0;

    /* for avg latency, if no saddr/daddr specified, use 0(addr) as key */
    u64 addr = 0;

    bpf_probe_read_kernel(&sport, sizeof(sport), (void *)&inet->inet_sport);
    bpf_probe_read_kernel(&dport, sizeof(dport), (void *)&inet->inet_dport);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), (void *)&inet->inet_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), (void *)&inet->inet_daddr);
    bpf_probe_read_kernel(&family, sizeof(family), (void *)&sk->__sk_common.skc_family);

    LPORTFILTER
    RPORTFILTER
    LADDRFILTER
    RADDRFILTER
    FAMILYFILTER

    int one = 1;
    int *stateidx = resultstate.lookup(&one);
    if (stateidx == NULL) {
        return -1;
    }
    if (*stateidx != CONG_STATE_CA) {
        bpf_trace_printk("Switching to CA %ull", bpf_ktime_get_ns());
    }
    *stateidx = CONG_STATE_CA;
    return 0;
}


int trace_tcp_rcv(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    struct tcp_sock *ts = tcp_sk(sk);
    u32 srtt = ts->srtt_us >> 3;
    const struct inet_sock *inet = inet_sk(sk);

    /* filters */
    u16 sport = 0;
    u16 dport = 0;
    u32 saddr = 0;
    u32 daddr = 0;
    u16 family = 0;

    /* for histogram */
    sock_key_t key;

    /* for avg latency, if no saddr/daddr specified, use 0(addr) as key */
    u64 addr = 0;

    bpf_probe_read_kernel(&sport, sizeof(sport), (void *)&inet->inet_sport);
    bpf_probe_read_kernel(&dport, sizeof(dport), (void *)&inet->inet_dport);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), (void *)&inet->inet_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), (void *)&inet->inet_daddr);
    bpf_probe_read_kernel(&family, sizeof(family), (void *)&sk->__sk_common.skc_family);

    LPORTFILTER
    RPORTFILTER
    LADDRFILTER
    RADDRFILTER
    FAMILYFILTER

    // if not in slow start, just get out; don't store result
    int one = 1;
    int *stateidx = resultstate.lookup(&one);
    if (stateidx == NULL) {
        return -1;
    }
    if (*stateidx != CONG_STATE_SS) {
        return 0;
    }

    u32 srtt_us = srtt;
    srtt /= 1000;

    STORE_HIST


    // key.slot = bpf_log2l(srtt);
    // key.slot = srtt;
    // hist_srtt.atomic_increment(key);
    // hist_srtt.increment(key);

    sock_latency_t newlat = {0};
    sock_latency_t *lat;
    lat = latency.lookup(&addr);
    if (!lat) {
        newlat.latency += srtt;
        newlat.count += 1;
        latency.update(&addr, &newlat);
    } else {
        lat->latency += srtt;
        lat->count += 1;
    }

    int zero = 0;
    int *resultsidx = resultstate.lookup(&zero);
    if (resultsidx == NULL) {
        return -1;
    }
    int new_results = (int)*resultsidx;
    lock_xadd(resultsidx, 1);

    new_results = new_results % MAXRESULTS;
    struct latency_sample *latsamp = results.lookup(&new_results);
    if (latsamp == NULL) {
        return -1;
    }
    latsamp->timestamp = bpf_ktime_get_ns(); 
    latsamp->rtt = srtt_us;

    return 0;
}
"""

# filter for local port
if args.lport:
    bpf_text = bpf_text.replace('LPORTFILTER',
        """if (ntohs(sport) != %d)
        return 0;""" % int(args.lport))
else:
    bpf_text = bpf_text.replace('LPORTFILTER', '')

# filter for remote port
if args.rport:
    bpf_text = bpf_text.replace('RPORTFILTER',
        """if (ntohs(dport) != %d)
        return 0;""" % int(args.rport))
else:
    bpf_text = bpf_text.replace('RPORTFILTER', '')

# filter for local address
if args.laddr:
    bpf_text = bpf_text.replace('LADDRFILTER',
        """if (saddr != %d)
        return 0;""" % struct.unpack("=I", socket.inet_aton(args.laddr))[0])
else:
    bpf_text = bpf_text.replace('LADDRFILTER', '')

# filter for remote address
if args.raddr:
    bpf_text = bpf_text.replace('RADDRFILTER',
        """if (daddr != %d)
        return 0;""" % struct.unpack("=I", socket.inet_aton(args.raddr))[0])
else:
    bpf_text = bpf_text.replace('RADDRFILTER', '')
if args.ipv4:
    bpf_text = bpf_text.replace('FAMILYFILTER',
        'if (family != AF_INET) { return 0; }')
elif args.ipv6:
    bpf_text = bpf_text.replace('FAMILYFILTER',
        'if (family != AF_INET6) { return 0; }')
else:
    bpf_text = bpf_text.replace('FAMILYFILTER', '')

label = "msecs"

print_header = "srtt"
# show byladdr/byraddr histogram
if args.byladdr:
    bpf_text = bpf_text.replace('STORE_HIST', 'key.addr = addr = saddr;')
    print_header = "Local Address"
elif args.byraddr:
    bpf_text = bpf_text.replace('STORE_HIST', 'key.addr = addr = daddr;')
    print_header = "Remote Addres"
else:
    bpf_text = bpf_text.replace('STORE_HIST', 'key.addr = addr = 0;')
    print_header = "All Addresses"

# debug/dump ebpf enable or not
if args.debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_rcv_established", fn_name="trace_tcp_rcv")

print("Tracing TCP RTT... Hit Ctrl-C to end.")

def print_section(addr):
    addrstr = "*******"
    if (addr):
        addrstr = inet_ntop(AF_INET, struct.pack("I", addr))

    avglat = ""
    lats = b.get_table("latency")
    lat = lats[ctypes.c_ulong(addr)]
    avglat = " [AVG %d]" % (lat.latency / lat.count)

    return addrstr + avglat

def _log_kernel_messages(b):
    while True:
        task,pid,cpu,flags,ts,msg = b.trace_fields(nonblocking=True)
        if task is None:
            break
        print("trace_printk: ktime {} cpu{} {} flags:{} {}".format(ts, cpu, task.decode(errors='ignore'), flags.decode(errors='ignore'), msg.decode(errors='ignore')).replace('%',''))


# output
exiting = 0 if args.interval else 1
# dist = b.get_table("hist_srtt")
lathash = b.get_table("latency")
results = b.get_table("results")
resultstate = b.get_table("resultstate")

seconds = 0
while (1):
    try:
        sleep(int(args.interval))
        seconds = seconds + int(args.interval)
    except KeyboardInterrupt:
        exiting = 1

    print()
    print("%-8s\n" % strftime("%H:%M:%S"), end="")

    # dist.print_linear_hist(label, section_header=print_header, section_print_fn=print_section)
    # dist.clear()
    lathash.clear()

    #_log_kernel_messages(b)

    if exiting or seconds >= args.duration:
        rcount = resultstate[0].value
        print(rcount)
        #for k,v in resultstate.items():
        #    print(f"resultstate {k} {v}")
        #for k,v in results.items():
        #    print(f"results {k} {v}")
        with open(args.output, "w") as outfile:
            csvout = csv.writer(outfile) 
            csvout.writerow(["sample","timestamp","rtt"])
            for i in range(rcount):
                sample = results[i]
                csvout.writerow([i, sample.timestamp, sample.rtt])

        exit()
