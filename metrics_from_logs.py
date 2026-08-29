"""
Real Metrics Analyzer
=======================
Computes actual performance metrics from real log files produced by
enterprise_security_controller_v2.py and availability_prober.py.

This is the direct replacement for the hardcoded self.comparison_data /
self.simulation_metrics dictionaries in the original performance_evaluation.py.
Every number this script prints or saves is derived from real log data.

REQUIRED INPUT: a ground_truth.json file YOU create, describing which
source IPs were actually attackers and during which time windows, e.g.:

{
  "attack_windows": [
    {"src_ip": "10.0.0.13", "attack_type": "SYN_FLOOD", "start": 1785600000.0, "end": 1785600030.0},
    {"src_ip": "10.0.0.13", "attack_type": "UDP_FLOOD", "start": 1785600040.0, "end": 1785600070.0}
  ],
  "legitimate_ips": ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
                       "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9", "10.0.0.10",
                       "10.0.0.11", "10.0.0.12"]
}

This ground truth is unavoidable and cannot be automated away: only you
know, from your own attack_scenarios.py invocation script, exactly which
IP launched which attack and exactly when -- log this at attack launch
time (a single `print(time.time())` before/after each attack call is enough).
"""

import json
import sys
import argparse
from collections import defaultdict


def load_jsonl(path):
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def is_attack_window(src_ip, ts, attack_windows):
    for w in attack_windows:
        if w['src_ip'] == src_ip and w['start'] <= ts <= w['end']:
            return True, w['attack_type']
    return False, None


def compute_detection_metrics(decisions, ground_truth):
    attack_windows = ground_truth['attack_windows']
    legitimate_ips = set(ground_truth['legitimate_ips'])
    attacker_ips = set(w['src_ip'] for w in attack_windows)

    tp = fp = tn = fn = 0
    contained_attacks = defaultdict(bool)   # (src_ip, attack_type) -> was ever contained
    false_containments = []                  # legitimate flows that got RATE_LIMIT/QUARANTINE/BLOCK
    response_times = []
    per_attack_type_total = defaultdict(int)
    per_attack_type_contained = defaultdict(set)

    for d in decisions:
        src, ts, action = d['src_ip'], d['t_detect_start'], d['action']
        in_attack, attack_type = is_attack_window(src, ts, attack_windows)
        contained = action in ('RATE_LIMIT', 'QUARANTINE', 'BLOCK')

        if in_attack:
            per_attack_type_total[attack_type] += 1
            if contained:
                tp += 1
                per_attack_type_contained[attack_type].add((src, ts))
                response_times.append(d['total_s'])
            else:
                fn += 1
        elif src in legitimate_ips:
            if contained:
                fp += 1
                false_containments.append(d)
            else:
                tn += 1
        # src not in either set (unknown/unlabeled) -- skipped from strict metrics

    n_attack = tp + fn
    n_legit = fp + tn

    containment_rate = (tp / n_attack * 100) if n_attack else None
    false_positive_rate = (fp / n_legit * 100) if n_legit else None
    false_containment_rate = false_positive_rate  # same definition here: legit flow wrongly acted on

    per_attack_cr = {}
    for atype, total in per_attack_type_total.items():
        contained_n = len(per_attack_type_contained[atype])
        per_attack_cr[atype] = {
            'total_detections_in_window': total,
            'unique_contained_events': contained_n,
        }

    return {
        'true_positives': tp, 'false_negatives': fn,
        'false_positives': fp, 'true_negatives': tn,
        'containment_rate_percent': containment_rate,
        'false_positive_rate_percent': false_positive_rate,
        'false_containment_rate_percent': false_containment_rate,
        'response_time_seconds': {
            'n_samples': len(response_times),
            'mean': (sum(response_times) / len(response_times)) if response_times else None,
            'min': min(response_times) if response_times else None,
            'max': max(response_times) if response_times else None,
        },
        'per_attack_type': per_attack_cr,
        'n_false_containment_events': len(false_containments),
    }


def compute_availability(availability_records):
    if not availability_records:
        return None
    total = len(availability_records)
    success = sum(1 for r in availability_records if r['success'])
    return {
        'network_availability_percent': (success / total * 100) if total else None,
        'n_probes': total,
        'n_successful': success,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--decisions', required=True, help='Path to decisions_*.jsonl from the controller')
    ap.add_argument('--ground-truth', required=True, help='Path to ground_truth.json')
    ap.add_argument('--availability', default=None, help='Path to availability_*.jsonl (optional)')
    ap.add_argument('--out', default='real_metrics_summary.json')
    args = ap.parse_args()

    decisions = load_jsonl(args.decisions)
    with open(args.ground_truth) as f:
        ground_truth = json.load(f)

    detection_metrics = compute_detection_metrics(decisions, ground_truth)

    availability_metrics = None
    if args.availability:
        availability_records = load_jsonl(args.availability)
        availability_metrics = compute_availability(availability_records)

    result = {
        'source_files': {
            'decisions': args.decisions,
            'ground_truth': args.ground_truth,
            'availability': args.availability,
        },
        'n_total_decisions': len(decisions),
        'detection_and_containment': detection_metrics,
        'availability': availability_metrics,
    }

    print(json.dumps(result, indent=2))
    with open(args.out, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved: {args.out}")

    if detection_metrics['containment_rate_percent'] is None:
        print("\nWARNING: no attack-window decisions matched -- check that your "
              "ground_truth.json timestamps actually overlap the decisions log's "
              "t_detect_start values (both should be time.time() epoch seconds).")


if __name__ == '__main__':
    main()
