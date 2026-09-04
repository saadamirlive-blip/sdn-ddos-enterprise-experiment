"""
Availability Prober
====================
Run this INSIDE your Mininet CLI session (or via a Mininet script) while
attacks are running, to produce real Network Availability data.

Usage from the Mininet CLI:
    mininet> py exec(open('availability_prober.py').read())
    mininet> py probe_all_pairs(net, duration=300, interval=3)

This pings every host pair every `interval` seconds for `duration` seconds
and writes a JSONL log of (src, dst, success, timestamp) records. Network
Availability (NA) is then computed for real in metrics_from_logs.py as:
    NA(t) = (# successful pairs at time t) / (N * (N-1)) * 100%
matching Eq. (8) in the manuscript -- but from measured pings, not a
hand-typed number.
"""

import time
import json
import os
import threading


def run_host_command(host, command):
    """Serialize commands because Mininet Host shells cannot be polled concurrently."""
    lock = getattr(host, '_experiment_cmd_lock', None)
    if lock is None:
        lock = threading.Lock()
        host._experiment_cmd_lock = lock
    with lock:
        return host.cmd(command)


def probe_all_pairs(net, duration=300, interval=3, log_path=None, stop_event=None,
                    exclude_hosts=None):
    if log_path is None:
        log_path = f'availability_{time.strftime("%Y%m%d_%H%M%S")}.jsonl'

    # Exclude quarantine-collector infrastructure hosts (hq1/hq2/hq3) --
    # operational-pairs denominator in the paper's Availability formula (Eq. 8).
    excluded = set(exclude_hosts or ())
    hosts = [h for h in net.hosts
             if not h.name.startswith('hq') and h.name not in excluded]
    print(f"Probing {len(hosts)} hosts x {len(hosts)-1} pairs every {interval}s for {duration}s")
    print(f"Logging to {log_path}")

    start = time.time()
    with open(log_path, 'a', buffering=1) as f:
        while time.time() - start < duration and not (stop_event and stop_event.is_set()):
            round_start = time.time()
            for src in hosts:
                for dst in hosts:
                    if stop_event and stop_event.is_set():
                        break
                    if src == dst:
                        continue
                    # -c 1 -W 1: one packet, 1s timeout -- fast enough for
                    # frequent polling without flooding the network itself
                    result = run_host_command(
                        src, f'timeout 0.5 ping -c 1 -W 0.2 {dst.IP()}'
                    )
                    success = ('0% packet loss' in result or
                               '1 received' in result or
                               ', 1 packets received' in result)
                    f.write(json.dumps({
                        'timestamp': time.time(),
                        'src': src.name, 'src_ip': src.IP(),
                        'dst': dst.name, 'dst_ip': dst.IP(),
                        'success': bool(success),
                    }) + '\n')
            elapsed_round = time.time() - round_start
            sleep_for = max(0, interval - elapsed_round)
            if stop_event:
                stop_event.wait(sleep_for)
            else:
                time.sleep(sleep_for)

    print(f"Done. Availability log: {log_path}")
    return log_path
