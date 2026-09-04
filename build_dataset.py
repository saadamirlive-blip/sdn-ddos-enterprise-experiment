"""Package measured trial artifacts into a reproducible dataset directory."""

import argparse
import csv
import glob
import json
import os
import shutil
from pathlib import Path


DECISION_FIELDS = [
    'source', 'src_ip', 'dst_ip', 'pps', 'bps', 'proto', 'p_attack',
    'severity', 'action', 't_detect_start', 't_decide', 't_enforce_done',
    'total_s', 'wall_clock',
]
AVAILABILITY_FIELDS = [
    'timestamp', 'src', 'src_ip', 'dst', 'dst_ip', 'success',
]


def load_jsonl(path):
    with open(path) as stream:
        return [json.loads(line) for line in stream if line.strip()]


def write_csv(path, rows, fields):
    with open(path, 'w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def latest_availability(trial_dir):
    candidates = glob.glob(os.path.join(trial_dir, 'availability_*.jsonl'))
    return max(candidates, key=os.path.getmtime) if candidates else None


def build_dataset(trials, output_dir, baselines_path, reference_metrics_path=None):
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    all_decisions = []
    all_availability = []
    manifest_trials = []

    for trial in trials:
        trial_path = Path(trial)
        decisions_path = trial_path / 'decisions.jsonl'
        ground_truth_path = trial_path / 'ground_truth.json'
        summary_path = trial_path / 'real_metrics_summary.json'
        availability_path = latest_availability(str(trial_path))
        if not all(path.exists() for path in (decisions_path, ground_truth_path, summary_path)):
            continue
        if availability_path is None:
            continue

        dataset_trial = output / trial_path.name
        dataset_trial.mkdir(exist_ok=True)
        for source in (decisions_path, ground_truth_path, summary_path, Path(availability_path)):
            shutil.copy2(source, dataset_trial / source.name)

        decisions = load_jsonl(decisions_path)
        availability = load_jsonl(availability_path)
        all_decisions.extend(decisions)
        all_availability.extend(availability)
        manifest_trials.append({
            'trial': trial_path.name,
            'decisions': str(dataset_trial / decisions_path.name),
            'ground_truth': str(dataset_trial / ground_truth_path.name),
            'availability': str(dataset_trial / Path(availability_path).name),
            'summary': str(dataset_trial / summary_path.name),
            'n_decisions': len(decisions),
            'n_availability_records': len(availability),
        })

    write_csv(output / 'decisions.csv', all_decisions, DECISION_FIELDS)
    write_csv(output / 'availability.csv', all_availability, AVAILABILITY_FIELDS)
    if baselines_path and os.path.exists(baselines_path):
        shutil.copy2(baselines_path, output / 'baselines_reference.json')
    if reference_metrics_path and os.path.exists(reference_metrics_path):
        shutil.copy2(reference_metrics_path, output / 'paper_reference_metrics.json')

    manifest = {
        'dataset_status': 'measured_trial_artifacts',
        'source_trials': manifest_trials,
        'n_decisions': len(all_decisions),
        'n_availability_records': len(all_availability),
        'baseline_status': 'external_reference_values_not_rerun',
        'baseline_source': baselines_path,
        'paper_reference_status': 'supplied_summary_not_rerun',
        'paper_reference_source': reference_metrics_path,
    }
    with open(output / 'manifest.json', 'w') as stream:
        json.dump(manifest, stream, indent=2)
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--trials', nargs='+', required=True)
    parser.add_argument('--output', default='dataset')
    parser.add_argument('--baselines', default='metrics/baselines_reference.json')
    parser.add_argument('--reference-metrics', default='metrics/metrics_summary.json')
    args = parser.parse_args()
    manifest = build_dataset(
        args.trials, args.output, args.baselines, args.reference_metrics
    )
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
