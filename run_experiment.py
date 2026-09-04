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
    sudo python3 run_experiment.py --attacker h4 --victim h11 --duration 300 --trial-dir trial_01
"""

import argparse
import json
import os

import sys
import threading
import time


def run_host_command(host, command):
    """Serialize commands because Mininet Host shells cannot be polled concurrently."""
    lock = getattr(host, '_experiment_cmd_lock', None)
    if lock is None:
        lock = threading.Lock()
        host._experiment_cmd_lock = lock
    with lock:
        return host.cmd(command)

from mininet.net import Mininet
from mininet.log import setLogLevel
import subprocess

from topology_enterprise import (EnterpriseTopo, NonBlockingOVSSwitch,
                                  clean_leftover_network, get_controller_port,
                                  is_ovs_kernel_loaded)
from attack_scenarios import AttackScenarios
from availability_prober import probe_all_pairs


def start_background_traffic(net, legitimate_hosts, victim_name, stop_event):
    """Continuous benign iPerf3 traffic between legitimate hosts, matching
    the paper's Section IV-C description (HTTP/HTTPS/SQL/file-transfer-like
    background load). Runs until stop_event is set."""
    victim = net.get(victim_name)
    processes = []
    processes.append(victim.popen('iperf3 -s', shell=True))

    def loop():
        while not stop_event.is_set():
            for hname in legitimate_hosts:
                if stop_event.is_set():
                    break
                h = net.get(hname)
                # Use a child process instead of Host.cmd so availability
                # probes never compete with a polling operation on this host.
                processes.append(h.popen(
                    f'timeout 3 iperf3 -u -b 5K -c {victim.IP()} -t 2', shell=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                ))
                time.sleep(4)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    t.processes = processes
    return t


def run_trial(attacker_name, victim_name, duration, trial_dir, controller_logs_dir='logs'):
    os.makedirs(trial_dir, exist_ok=True)
    trial_start = time.time()
    setLogLevel('info')

    print("Cleaning leftover interfaces...")
    clean_leftover_network()
    target_port = get_controller_port()
    if target_port is None:
        raise RuntimeError(
            "No Ryu OpenFlow listener found on ports 6653 or 6633. "
            "Start enterprise_security_controller_v2.py before running a trial."
        )
    NonBlockingOVSSwitch.target_controller_port = target_port
    print(f"Controller detected on port {target_port}. If this is wrong, "
          f"start enterprise_security_controller_v2.py FIRST.")

    topo = EnterpriseTopo()
    net = Mininet(topo=topo, controller=None, switch=NonBlockingOVSSwitch, waitConnected=False)
    net.start()

    use_netdev = not is_ovs_kernel_loaded()
    for s in ['s0', 's1', 's2', 's3']:
        if use_netdev:
            subprocess.run(['ovs-vsctl', '--no-wait', 'set', 'bridge', s, 'datapath_type=netdev'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
    background_thread = start_background_traffic(
        net, legitimate_hosts[:1], victim_name, stop_bg
    )

    # ---- Start availability prober in a background thread ---- #
    avail_log = os.path.join(trial_dir, f'availability_{time.strftime("%Y%m%d_%H%M%S")}.jsonl')
    stop_availability = threading.Event()
    avail_thread = threading.Thread(
        target=probe_all_pairs, args=(net,), kwargs={
            'duration': duration, 'interval': 5, 'log_path': avail_log,
            'stop_event': stop_availability,
            'exclude_hosts': {attacker_name},
        },
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
    attack_duration = max(1, min(25, (duration - 5 * 5) // 6))
    run_and_record(attacks.syn_flood_attack, 'SYN_FLOOD', victim_ip, duration=attack_duration, intensity='high')
    run_and_record(attacks.udp_flood_attack, 'UDP_FLOOD', victim_ip, duration=attack_duration, intensity='high')
    run_and_record(attacks.icmp_flood_attack, 'ICMP_FLOOD', victim_ip, duration=attack_duration)
    run_and_record(attacks.mixed_ddos_attack, 'MIXED_DDOS', victim_ip, duration=attack_duration)
    run_and_record(attacks.slowloris_attack, 'SLOWLORIS', victim_ip, duration=attack_duration)
    run_and_record(attacks.http_flood_attack, 'HTTP_FLOOD', victim_ip, duration=attack_duration)

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
    background_thread.join()
    for process in getattr(background_thread, 'processes', []):
        if process.poll() is None:
            process.terminate()
    stop_availability.set()
    avail_thread.join()
    print("\nTrial complete. Stopping network...")
    net.stop()

    # ---- Copy only this trial's controller decisions into its artifact folder ---- #
    import glob
    import shutil
    decisions_copy_path = None
    candidates = sorted(glob.glob(os.path.join(controller_logs_dir, 'decisions_*.jsonl')),
                         key=os.path.getmtime, reverse=True)
    if candidates:
        newest = candidates[0]
        decisions_copy_path = os.path.join(trial_dir, 'decisions.jsonl')
        trial_end = time.time()
        with open(newest) as source, open(decisions_copy_path, 'w') as target:
            copied = 0
            for line in source:
                if not line.strip():
                    continue
                record = json.loads(line)
                wall_clock = record.get('wall_clock', record.get('t_detect_start', 0))
                if trial_start <= wall_clock <= trial_end:
                    target.write(json.dumps(record) + '\n')
                    copied += 1
        print(f"Copied {copied} trial decisions: {newest} -> {decisions_copy_path}")
    else:
        print(f"WARNING: no decisions_*.jsonl found in {controller_logs_dir}/ -- "
              f"is the controller running with --controller-logs-dir pointing at the "
              f"right folder? You will need to copy it into {trial_dir}/decisions.jsonl "
              f"manually before running the report generator.")

    print(f"\nTrial artifacts in: {trial_dir}/")
    print(f"  - ground_truth.json")
    print(f"  - {os.path.basename(avail_log)}")
    print(f"  - decisions.jsonl" if decisions_copy_path else "  - decisions.jsonl (MISSING -- see warning above)")

    # ---- Auto-compute real metrics for this trial ---- #
    if decisions_copy_path:
        try:
            from metrics_from_logs import load_jsonl, compute_detection_metrics, compute_availability
            decisions = load_jsonl(decisions_copy_path)
            avail_records = load_jsonl(avail_log) if os.path.exists(avail_log) else []
            det = compute_detection_metrics(decisions, ground_truth)
            avail = compute_availability(avail_records)
            summary = {'detection_and_containment': det, 'availability': avail}
            summary_path = os.path.join(trial_dir, 'real_metrics_summary.json')
            with open(summary_path, 'w') as f:
                json.dump(summary, f, indent=2)
            print(f"  - real_metrics_summary.json (auto-computed)")
            print(f"\nCR={det['containment_rate_percent']}  "
                  f"FPR={det['false_positive_rate_percent']}  "
                  f"NA={avail['network_availability_percent'] if avail else None}")
        except Exception as e:
            print(f"WARNING: could not auto-compute metrics ({e}). "
                  f"Run metrics_from_logs.py manually on this trial's files instead.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--attacker', default='h4', help='Attacker host name (must match topology)')
    ap.add_argument('--victim', default='h11', help='Victim host name')
    ap.add_argument('--duration', type=int, default=300, help='Total trial duration in seconds')
    ap.add_argument('--trial-dir', default='trial_01', help='Output folder for this trial')
    ap.add_argument('--controller-logs-dir', default='logs',
                     help='Folder where the controller writes decisions_*.jsonl (relative to where ryu-manager was launched)')
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("This script must be run with sudo (Mininet requires root).")
        sys.exit(1)

    run_trial(args.attacker, args.victim, args.duration, args.trial_dir, args.controller_logs_dir)


if __name__ == '__main__':
    main()
