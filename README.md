# SDN Enterprise Security Controller & Automated Evaluation

Automated SDN framework for DDoS attack detection, mitigation, and real-time network availability evaluation using Ryu controller, Mininet, and Machine Learning.

## 🚀 Quick Start in GitHub Codespaces

1. Click **`< > Code`** > **`Codespaces`** > **`Create codespace on main`**.
2. The environment will automatically install Mininet, Open vSwitch, Ryu, and Python dependencies via `.devcontainer`.

---

## 📋 Running Experiments

### Step 1: Train the Machine Learning Model
```bash
python3 train_model.py
```
*Generates `model.pkl` and `scaler.pkl`.*

### Step 2: Start Ryu Security Controller (Terminal 1)
```bash
sudo ryu-manager enterprise_security_controller_v2.py
```
*Keep this terminal running.*

### Step 3: Run Automated Experiment Trial (Terminal 2)
```bash
sudo python3 run_experiment.py --attacker h13 --victim h11 --duration 300 --trial-dir trial_01
```
*Runs the full topology, background legitimate traffic, 6 attack scenarios, availability probing, and telemetry logging.*

### Step 4: Compute Experiment Metrics
```bash
python3 metrics_from_logs.py \
    --decisions logs/decisions_<TIMESTAMP>.jsonl \
    --ground-truth trial_01/ground_truth.json \
    --availability trial_01/availability_<TIMESTAMP>.jsonl \
    --out trial_01/real_metrics_summary.json
```

---

## 📁 Repository Structure
- `enterprise_security_controller_v2.py`: Ryu OpenFlow controller with ML and per-switch quarantine fallback.
- `topology_enterprise.py`: Enterprise network topology with quarantine collector hosts (`hq1`, `hq2`, `hq3`).
- `run_experiment.py`: Orchestrator for automated end-to-end trials.
- `attack_scenarios.py`: Multi-vector DDoS attack generators (SYN, UDP, ICMP, HTTP flood, Slowloris, Port Scan).
- `availability_prober.py`: Probing engine measuring legitimate host availability.
- `metrics_from_logs.py`: Evaluator computing containment rate, response time, and false positive rates.
- `train_model.py`: Random Forest classifier training pipeline.
- `FINAL_RUN_GUIDE.md`: Detailed testing and trial guide.
