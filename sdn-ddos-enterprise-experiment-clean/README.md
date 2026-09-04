# SDN Enterprise DDoS Security Experiment

## Clean Codespace Start

This folder is a source-only starting point. It intentionally contains no
trial folders, controller logs, trained model files, generated reports, or
dataset rows. Open this folder as the Codespace root; `.devcontainer/setup.sh`
installs Mininet/Open vSwitch dependencies and trains the initial model.

After the Codespace finishes setup, run:

```bash
./run_pipeline.sh 1 60
```

For the full experiment, use:

```bash
./run_pipeline.sh 10 300
```

The first run creates `model.pkl`, `scaler.pkl`, `logs/`, `trial_XX/`,
`dataset/`, and `Results_Report.docx` locally in the new Codespace.

Automated SDN Security Experimentation Framework evaluating Machine Learning-based DDoS detection, mitigation, and host containment in an enterprise OpenFlow/Mininet network.

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/saadamirlive-blip/sdn-ddos-enterprise-experiment)

---

## 🚀 One-Click Run in GitHub Codespaces

1. Click **[Open in GitHub Codespaces](https://codespaces.new/saadamirlive-blip/sdn-ddos-enterprise-experiment)**.
2. The environment automatically builds and installs Mininet, Open vSwitch, Ryu SDN controller, and all dependencies.
3. Open a terminal in the Codespace and run:

```bash
chmod +x run_pipeline.sh
./run_pipeline.sh
```

> **Note**: To run all 10 trials with full 300-second duration:
> ```bash
> ./run_pipeline.sh 10 300
> ```

---

## 📋 Manual Pipeline Execution (Step-by-Step)

Refer to **[MASTER_PIPELINE.md](MASTER_PIPELINE.md)** for detailed phase-by-phase instructions:

1. **Train Model:**
   ```bash
   python3 train_model.py
   ```
2. **Start Security Controller (Terminal 1):**
   ```bash
   ryu-manager enterprise_security_controller_v2.py
   ```
3. **Run Trial (Terminal 2):**
   ```bash
   sudo python3 run_experiment.py --attacker h4 --victim h11 --duration 300 --trial-dir trial_01
   ```
4. **Compute Metrics:**
   ```bash
   python3 metrics_from_logs.py --decisions logs/decisions_*.jsonl --ground-truth trial_01/ground_truth.json --availability trial_01/availability_*.jsonl --out trial_01/real_metrics_summary.json
   ```
5. **Generate Final Results Report (.docx):**
   ```bash
   python3 generate_results_report.py --model-metrics model_metrics.json --trials trial_01 trial_02 trial_03 --decisions-dir logs --baselines metrics/baselines_reference.json --reference-metrics metrics/metrics_summary.json --out Results_Report.docx
   ```

The baseline comparison values in `metrics/baselines_reference.json` come from
the supplied research-result summary. They are labeled as external reference
values in the report and are not treated as rerun measurements. Proposed-system
metrics remain derived from each trial's controller, ground-truth, and
availability logs.

---

## 📂 Core Files
- `topology_enterprise.py`: 4 OpenFlow switches, 13 hosts, 3 quarantine collectors.
- `enterprise_security_controller_v2.py`: Ryu ML detection and port containment controller.
- `train_model.py`: Trains Random Forest DDoS classifier and exports metrics.
- `attack_scenarios.py`: Multi-vector DDoS generator (SYN, UDP, ICMP, Slowloris, HTTP flood).
- `availability_prober.py`: Real-time network availability matrix prober.
- `run_experiment.py`: Automated trial orchestrator with background traffic.
- `metrics_from_logs.py`: Computes CR, FPR, FCR, mitigation response time, and availability.
- `generate_results_report.py`: Generates publication-ready Word report with charts.
.
