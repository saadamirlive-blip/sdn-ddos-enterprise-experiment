# MASTER PIPELINE -- The Only Guide You Need

This replaces RUN_GUIDE.md and FINAL_RUN_GUIDE.md from earlier in this
conversation -- ignore those two, use only this one.

---

## The 9 files, and what each one is for

| # | File | Status | What it does |
|---|---|---|---|
| 1 | `devcontainer.json` | Original, unused for cloud VM | Only needed if you later switch to GitHub Codespaces/Docker |
| 2 | `topology_enterprise.py` | **Updated** | Defines the network: 4 switches, 13 hosts + 3 quarantine collectors, h4 = attacker |
| 3 | `train_model.py` | **Updated** | Trains the Random Forest classifier, now also exports real metrics to JSON |
| 4 | `enterprise_security_controller_v2.py` | **Updated (fixed)** | The Ryu controller -- detects and contains attacks, logs every real decision |
| 5 | `attack_scenarios.py` | **Updated** | Attack-generation functions (SYN/UDP/ICMP/Mixed/Slowloris/HTTP flood), reused as-is |
| 6 | `availability_prober.py` | **Updated** | Pings all host pairs during a trial to measure real Network Availability |
| 7 | `run_experiment.py` | **New** | Runs one complete trial automatically: topology + traffic + attacks + probing |
| 8 | `metrics_from_logs.py` | Unchanged | Computes real CR/FPR/FCR/response-time/NA from one trial's logs |
| 9 | `generate_results_report.py` | **New** | Builds the final Word report with every figure, from all trials combined |

**Do not use:** `performance_evaluation.py` or the original `enterprise_security_controller.py` (pre-fix) -- these contain hardcoded numbers / the detection bug and are not part of this pipeline.

---

## Pipeline overview (5 phases, in order)

```
Phase 0: Environment setup           (once)
Phase 1: Train the model             (once)          -> file 3
Phase 2: Start the controller        (once, kept running in Terminal 1) -> file 4
Phase 3: Run 10 trials                (repeated x10, Terminal 2) -> files 2,5,6,7
Phase 4: Compute metrics per trial   (repeated x10) -> file 8
Phase 5: Generate the final report   (once, after all trials)  -> file 9
```

---

## Phase 0 -- Environment setup (once)

In your cloud VM's terminal:

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch python3-pip iperf3 hping3 netcat-openbsd
pip3 install ryu scikit-learn numpy pandas joblib matplotlib python-docx
```

Put all 9 files in one folder (e.g. `~/sdn-project/`) and `cd` into it.

---

## Phase 1 -- Train the model (once)

```bash
python3 train_model.py
```

**Produces:** `model.pkl`, `scaler.pkl`, `model_metrics.json`

Confirm all three files now exist:
```bash
ls model.pkl scaler.pkl model_metrics.json
```

---

## Phase 2 -- Start the controller (Terminal 1, leave running for ALL 10 trials)

```bash
sudo ryu-manager enterprise_security_controller_v2.py
```

**Confirm you see:** `ML loaded: True` and a line like `Decision log: .../logs/decisions_<timestamp>.jsonl`.

**Leave this terminal open and running for the entire rest of the pipeline** -- one controller process, one decision log, covering all 10 trials. Do not restart it between trials.

---

## Phase 3 -- Run a trial (Terminal 2, repeat 10 times)

```bash
sudo python3 run_experiment.py --attacker h4 --victim h11 --duration 300 --trial-dir trial_01
```

Then repeat with `trial_02`, `trial_03`, ... `trial_10` as the only thing that changes:

```bash
sudo python3 run_experiment.py --attacker h4 --victim h11 --duration 300 --trial-dir trial_02
sudo python3 run_experiment.py --attacker h4 --victim h11 --duration 300 --trial-dir trial_03
# ... up through trial_10
```

**Each run produces:** `trial_XX/ground_truth.json` and `trial_XX/availability_<timestamp>.jsonl`. (The decisions log from Phase 2 accumulates across all trials automatically -- you don't need to do anything extra for it.)

Each trial takes about 5 minutes (`--duration 300`), so budget ~50 minutes for all 10.

---

## Phase 4 -- Compute real metrics per trial (repeat 10 times, after each trial)

```bash
python3 metrics_from_logs.py \
    --decisions logs/decisions_<the timestamp from Phase 2>.jsonl \
    --ground-truth trial_01/ground_truth.json \
    --availability trial_01/availability_<timestamp>.jsonl \
    --out trial_01/real_metrics_summary.json
```

Repeat for `trial_02` through `trial_10`, changing only the trial folder name each time. You can do this right after each trial finishes, or batch all 10 at the end -- either works since the decisions log already has everything.

**Sanity check before moving on:** open one `real_metrics_summary.json` and make sure `containment_rate_percent` is not `null`. If it is, check the WARNING message `metrics_from_logs.py` printed -- it's almost always a timestamp mismatch between the two log files.

---

## Phase 5 -- Generate the final results report (once, after all 10 trials)

```bash
python3 generate_results_report.py \
    --model-metrics model_metrics.json \
    --trials trial_01 trial_02 trial_03 trial_04 trial_05 trial_06 trial_07 trial_08 trial_09 trial_10 \
    --decisions-dir logs \
    --out Results_Report.docx
```

**Produces:** `Results_Report.docx` -- every figure and table, generated from your real logs. Download this file from your VM and open it.

If any section says "SKIPPED" in red, that phase's data is missing or incomplete for at least one trial -- go back and check that trial's files before treating the report as final.

---

## One-page cheat sheet (copy-paste order)

```bash
# Phase 0 (once)
sudo apt update && sudo apt install -y mininet openvswitch-switch python3-pip iperf3 hping3 netcat-openbsd
pip3 install ryu scikit-learn numpy pandas joblib matplotlib python-docx

# Phase 1 (once)
python3 train_model.py

# Phase 2 (once, separate terminal, leave running)
sudo ryu-manager enterprise_security_controller_v2.py

# Phase 3 + 4, x10 (same terminal as Phase 3, one trial at a time)
sudo python3 run_experiment.py --attacker h4 --victim h11 --duration 300 --trial-dir trial_01
python3 metrics_from_logs.py --decisions logs/decisions_<ts>.jsonl --ground-truth trial_01/ground_truth.json --availability trial_01/availability_<ts>.jsonl --out trial_01/real_metrics_summary.json
# repeat both lines above for trial_02 ... trial_10

# Phase 5 (once, at the end)
python3 generate_results_report.py --model-metrics model_metrics.json --trials trial_01 trial_02 trial_03 trial_04 trial_05 trial_06 trial_07 trial_08 trial_09 trial_10 --decisions-dir logs --out Results_Report.docx
```
