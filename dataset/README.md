# Measured Dataset

This directory contains records copied from completed Mininet/Ryu trials.
It is not synthetic data.

- `manifest.json` records source trials and row counts.
- `trial_01/`, `trial_02/`, and `trial_03/` retain per-trial JSONL, ground truth, and summaries.
- `decisions.csv` combines controller decision records from those trials.
- `availability.csv` combines availability probe records from those trials.
- `baselines_reference.json` contains the supplied paper comparison values and is explicitly labeled as external reference data; no baseline implementation was rerun.
- `paper_reference_metrics.json` contains the supplied proposed-system summary and is kept separate from measured trial summaries.

Rebuild it after new trials with:

```bash
python3 build_dataset.py --trials trial_01 trial_02 trial_03 --output dataset --baselines metrics/baselines_reference.json
```
