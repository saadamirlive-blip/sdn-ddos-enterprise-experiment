#!/opt/sdn_venv/bin/python3
"""
Full Experiment Orchestrator
==============================
Runs ONE complete trial end-to-end, non-interactively:
  1. Starts the enterprise topology (reusing your existing topology_enterprise.py)
  2. Starts legitimate background traffic (iPerf3) between non-attacker hosts
  3. Runs each attack type from the attacker host, recording REAL ground truth
     (which IP, which attack type, exact start/end timestamps)
  4. Runs the availability prober concurrently in a background thread
  5. Cleanly tears down the network

Run this ONCE per Monte Carlo trial (the paper reports 10 trials -- run this
script 10 times, saving each trial's output to its own folder).

REQUIRES: the fixed controller (enterprise_security_controller_v2.py) already
running in a separate terminal BEFORE you start this script:
    ryu-manager enterprise_security_controller_v2.py

Usage:
    sudo python3 run_experiment.py --attacker h13 --victim h11 --duration 300 --trial-dir trial_01
"""

import argparse
import json
import os
import sys
import time
import threading

from mininet.net import Mininet
from mininet.log import setLogLevel
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from topology_enterprise import (EnterpriseTopo, NonBlockingOVSSwitch,
                                  clean_leftover_network, get_controller_port)
from attack_scenarios import AttackScenarios
from availability_prober import probe_all_pairs


def start_background_traffic(net, legitimate_hosts, victim_name, stop_event):
    """Continuous benign iPerf3 traffic between legitimate hosts, matching
    the paper's Section IV-C description (HTTP/HTTPS/SQL/file-transfer-like
    background load). Runs until stop_event is set."""
    victim = net.get(victim_name)
    victim.cmd('iperf3 -s -D')  # background iperf3 server on the victim
    time.sleep(1)

    def loop():
        while not stop_event.is_set():
            for hname in legitimate_hosts:
                if stop_event.is_set():
                    break
                h = net.get(hname)
                # Short client burst, then pause -- avoids saturating the
                # link and better resembles bursty enterprise traffic than
                # one continuous max-throughput stream.
                h.cmd(f'timeout 3 iperf3 -c {victim.IP()} -t 2 > /dev/null 2>&1 &')
                time.sleep(2)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


def run_trial(attacker_name, victim_name, duration, trial_dir):
    os.makedirs(trial_dir, exist_ok=True)
    setLogLevel('info')

    print("Cleaning leftover interfaces...")
    clean_leftover_network()
    target_port = get_controller_port()
    NonBlockingOVSSwitch.target_controller_port = target_port
    print(f"Controller detected on port {target_port}. If this is wrong, "
          f"start enterprise_security_controller_v2.py FIRST.")

    topo = EnterpriseTopo()
    net = Mininet(topo=topo, controller=None, switch=NonBlockingOVSSwitch, waitConnected=False)
    net.start()

    for s in ['s0', 's1', 's2', 's3']:
        subprocess.run(['ovs-vsctl', '--no-wait', 'set', 'bridge', s, 'protocols=OpenFlow13'],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['ovs-vsctl', '--no-wait', 'set-controller', s,
                         f'tcp:127.0.0.1:{target_port}'],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['ovs-vsctl', '--no-wait', 'set-fail-mode', s, 'standalone'],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    net.staticArp()
    print("Waiting 5s for switches to register with the controller...")
    time.sleep(5)

    all_hosts = [h.name for h in net.hosts if not h.name.startswith('hq')]
    legitimate_hosts = [h for h in all_hosts if h not in (attacker_name, victim_name)]
    attacker = net.get(attacker_name)
    victim = net.get(victim_name)

    print(f"Attacker: {attacker_name} ({attacker.IP()})  Victim: {victim_name} ({victim.IP()})")

    # ---- Start background legitimate traffic ---- #
    stop_bg = threading.Event()
    start_background_traffic(net, legitimate_hosts, victim_name, stop_bg)

    # ---- Start availability prober in a background thread ---- #
    avail_log = os.path.join(trial_dir, f'availability_{time.strftime("%Y%m%d_%H%M%S")}.jsonl')
    avail_thread = threading.Thread(
        target=probe_all_pairs, args=(net,), kwargs={'duration': duration, 'interval': 5, 'log_path': avail_log},
        daemon=True,
    )
    avail_thread.start()

    # ---- Run attacks with real ground-truth logging ---- #
    attacks = AttackScenarios(net)
    attacks.set_attacker(attacker)
    ground_truth = {"attack_windows": [], "legitimate_ips": [net.get(h).IP() for h in legitimate_hosts]}

    def run_and_record(fn, attack_type, *args, **kwargs):
        print(f"\n--- {attack_type} ---")
        start = time.time()
        fn(*args, **kwargs)
        end = time.time()
        ground_truth["attack_windows"].append({
            "src_ip": attacker.IP(), "attack_type": attack_type,
            "start": start, "end": end,
        })
        time.sleep(5)  # cool-down between attacks

    victim_ip = victim.IP()
    run_and_record(attacks.syn_flood_attack, 'SYN_FLOOD', victim_ip, duration=25, intensity='high')
    run_and_record(attacks.udp_flood_attack, 'UDP_FLOOD', victim_ip, duration=25, intensity='high')
    run_and_record(attacks.icmp_flood_attack, 'ICMP_FLOOD', victim_ip, duration=25)
    run_and_record(attacks.mixed_ddos_attack, 'MIXED_DDOS', victim_ip, duration=25)
    run_and_record(attacks.slowloris_attack, 'SLOWLORIS', victim_ip, duration=25)
    run_and_record(attacks.http_flood_attack, 'HTTP_FLOOD', victim_ip, duration=25)

    gt_path = os.path.join(trial_dir, 'ground_truth.json')
    with open(gt_path, 'w') as f:
        json.dump(ground_truth, f, indent=2)
    print(f"\nGround truth saved: {gt_path}")

    # ---- Let the availability prober finish out its window ---- #
    remaining = duration - sum(w['end'] - w['start'] + 5 for w in ground_truth['attack_windows'])
    if remaining > 0:
        print(f"Waiting {remaining:.0f}s for availability prober to finish its window...")
        time.sleep(remaining)

    stop_bg.set()
    print("\nTrial complete. Stopping network...")
    net.stop()
    print(f"Trial artifacts in: {trial_dir}/")
    print(f"  - ground_truth.json")
    print(f"  - {os.path.basename(avail_log)}")
    print(f"Remember: the controller's decisions_*.jsonl is in the controller's own logs/ folder.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--attacker', default='h13', help='Attacker host name (must match topology)')
    ap.add_argument('--victim', default='h11', help='Victim host name')
    ap.add_argument('--duration', type=int, default=300, help='Total trial duration in seconds')
    ap.add_argument('--trial-dir', default='trial_01', help='Output folder for this trial')
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("This script must be run with sudo (Mininet requires root).")
        sys.exit(1)

    run_trial(args.attacker, args.victim, args.duration, args.trial_dir)


if __name__ == '__main__':
    main()
