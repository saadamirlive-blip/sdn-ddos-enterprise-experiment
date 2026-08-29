# Complete Setup and Run Guide (Final, Consolidated)

This replaces the earlier RUN_GUIDE.md — it now covers every file, in the
correct order, including the orchestration script that runs a full trial
automatically instead of you typing commands into the Mininet CLI by hand.

## What changed in this final pass

- `topology_enterprise.py` -- added 3 quarantine-collector hosts (hq1/hq2/hq3), one per edge switch, connected last so their ports are predictable.
- `enterprise_security_controller_v2.py` -- the placeholder `QUARANTINE_COLLECTOR_PORT = 99` is gone, replaced with a real per-switch port mapping matching the new hosts above. Also fixed a fallback: if a switch isn't in that mapping, it now falls back to BLOCK instead of silently sending traffic to a port that doesn't exist.
- **New file**: `run_experiment.py` -- runs one full trial end-to-end (topology + background traffic + all 6 attacks with real ground-truth logging + availability probing), so you don't manually drive the Mininet CLI.
- `availability_prober.py` -- now correctly excludes the quarantine-collector hosts from the availability calculation.

## Full file list (9 files, all needed)

| File | Changed? | Purpose |
|---|---|---|
| `topology_enterprise.py` | Updated | Network topology, now includes quarantine collectors |
| `enterprise_security_controller_v2.py` | Updated | The fixed Ryu controller |
| `attack_scenarios.py` | Unchanged | Your original attack generator, reused as-is |
| `train_model.py` | Unchanged | Your original ML training script, reused as-is |
| `run_experiment.py` | **New** | Orchestrates one full trial automatically |
| `availability_prober.py` | Updated | Real availability measurement |
| `metrics_from_logs.py` | Unchanged | Computes real metrics from the logs |
| `devcontainer.json` | Unchanged | Your original container config |
| `performance_evaluation.py` | **Do not use** | This is the file with the hardcoded numbers -- keep it around for reference only, do not run it for real results |

---

## Step 0 -- One-time environment setup (inside your cloud VM / Codespace)

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch python3-pip iperf3 hping3 netcat-openbsd
pip3 install ryu scikit-learn numpy pandas joblib
```

Put all 9 files (the 7 Python files, `devcontainer.json`, and nothing from `performance_evaluation.py`'s numbers) in the same directory.

## Step 1 -- Train the model (once)

```bash
python3 train_model.py
```

This produces `model.pkl` and `scaler.pkl` in the same folder -- required before the controller will do anything beyond threshold-only fallback detection.

**Known gap, your call whether to fix now or later:** this script's synthetic traffic parameters (`pps ~ N(0.5, 0.2)` normal / `N(8.0, 3.0)` attack) don't match what your paper's Section IV-C currently states (`N(0.2, 0.05)` / `N(3.0, 0.5)`). Since you're now getting real numbers, the cleanest approach is: leave this file as-is, run everything, and update the paper's text to match whatever this script actually used -- rather than editing the script to match old paper text.

## Step 2 -- Start the controller (Terminal 1, leave running)

```bash
sudo ryu-manager enterprise_security_controller_v2.py
```

Confirm you see: `Decision log: .../logs/decisions_<timestamp>.jsonl` and `Controller v2 initialized. ML loaded: True`. If `ML loaded: False`, Step 1 didn't complete correctly -- fix that before continuing.

## Step 3 -- Run one full trial (Terminal 2)

```bash
sudo python3 run_experiment.py --attacker h13 --victim h11 --duration 300 --trial-dir trial_01
```

- `--attacker h13` matches your original topology's designated attacker; change if you've decided to use h4 instead (just make sure whichever you pick is excluded from `legitimate_hosts` correctly -- the script does this automatically based on whatever you pass).
- This single command handles topology startup, background legitimate traffic, all 6 attack types with ground-truth timestamps, availability probing, and clean teardown. It takes about 5 minutes (`--duration 300`).
- When it finishes, you'll have `trial_01/ground_truth.json` and `trial_01/availability_<timestamp>.jsonl`.

## Step 4 -- Compute real metrics for this trial

```bash
python3 metrics_from_logs.py \
    --decisions logs/decisions_<the timestamp the controller printed>.jsonl \
    --ground-truth trial_01/ground_truth.json \
    --availability trial_01/availability_<timestamp>.jsonl \
    --out trial_01/real_metrics_summary.json
```

Read the printed output. If `containment_rate_percent` comes back `null`, check the WARNING message it prints -- almost always means the timestamps in `ground_truth.json` and the decisions log aren't overlapping (double check your VM's clock/timezone didn't do anything unexpected between the two processes).

## Step 5 -- Repeat for 10 Monte Carlo trials

```bash
sudo python3 run_experiment.py --attacker h13 --victim h11 --duration 300 --trial-dir trial_02
sudo python3 run_experiment.py --attacker h13 --victim h11 --duration 300 --trial-dir trial_03
# ... through trial_10
```

Run Step 4 for each, then average `containment_rate_percent`, `false_positive_rate_percent`, `network_availability_percent`, and `response_time_seconds.mean` across all 10 `real_metrics_summary.json` files. These averages are what go in your paper's Table VIII.

## Step 6 -- Sanity-check before trusting the numbers

- Open one `decisions_*.jsonl` file and manually eyeball a few lines during a known attack window -- do the `severity` values actually spike, and does `action` actually escalate past MONITOR? If not, the feature-scaling constants in `_predict_attack_probability` (dividing real pps/bps by 1000 / 10,000,000) likely need retuning against what your VM's real hping3/Scapy traffic actually produces -- these constants were carried over from your original code and were never empirically validated against real traffic, only against the synthetic training set.
- If everything shows `action: "MONITOR"` throughout an attack window, that's a real, useful, honest finding -- it means the classifier/thresholds need tuning, not that something is broken in the logging pipeline.

## What's still a documented simplification, not a bug

- `severity = P_attack` only (no port-scan/auth-failure terms from the paper's full R_i(t) formula -- no telemetry source for those exists in this codebase).
- `F_critical` (Constraint 4 protection for critical flows) is not implemented in v2.
- QUARANTINE redirects to a dedicated collector host per switch rather than full 802.1Q VLAN trunking across the network.

None of these block you from getting real, honest results -- they just mean the paper's methodology section needs to describe accurately what was actually built, once you've decided whether to close these gaps or document them as limitations (see the "Manuscript Addendum" I gave you earlier for exact wording either way).
