#!/bin/bash
set -e

echo "========================================================="
echo " SDN Enterprise DDoS Experiment Pipeline Runner"
echo "========================================================="

# 0. Check and self-heal Python dependencies
if ! python3 -c "import pandas, sklearn, numpy, joblib, matplotlib, docx, ryu" 2>/dev/null; then
    echo "[Phase 0] Installing required dependencies (pandas, sklearn, ryu, etc.)..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq python3-pip python3-pandas python3-numpy python3-sklearn python3-matplotlib \
        iperf3 hping3 netcat-openbsd mininet openvswitch-switch
    sudo pip3 install --upgrade pip 2>/dev/null || true
    sudo pip3 install eventlet==0.30.2
    sudo pip3 install ryu python-docx joblib
fi

# Clean any lingering mininet/OVS state
sudo mn -c 2>/dev/null || true
sudo service openvswitch-switch start 2>/dev/null || true

if ! command -v ping >/dev/null 2>&1; then
    echo "[Setup] Installing ping for Mininet availability probes..."
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends iputils-ping
fi

# Recover existing containers where the setup hook did not install dependencies.
if ! python3 run_ryu_manager.py --help >/dev/null 2>&1; then
    echo "[Setup] Installing Python dependencies from requirements.txt..."
    python3 -m pip install 'setuptools<58'
    python3 -m pip install --no-build-isolation -r requirements.txt
fi

# Phase 1: Train model if not already trained
if [ ! -f "model.pkl" ] || [ ! -f "scaler.pkl" ] || [ ! -f "model_metrics.json" ]; then
    echo "[Phase 1] Training ML Model..."
    python3 train_model.py
else
    echo "[Phase 1] ML Model already trained (model.pkl, scaler.pkl, model_metrics.json exist)."
fi

# Phase 2: Start Ryu controller in background if not running
mkdir -p logs
if ! pgrep -f "run_ryu_manager.py" > /dev/null; then
    echo "[Phase 2] Starting Ryu Security Controller in background..."
    nohup python3 run_ryu_manager.py enterprise_security_controller_v2.py \
        > logs/controller.log 2>&1 < /dev/null &
    controller_ready=0
    for _ in $(seq 1 20); do
        if pgrep -f "run_ryu_manager.py" > /dev/null && \
           ss -ltn 2>/dev/null | awk '$4 ~ /:(6653|6633)$/ {found=1} END {exit !found}'; then
            controller_ready=1
            break
        fi
        sleep 1
    done
    if [ "$controller_ready" -eq 1 ]; then
        echo "   -> Ryu Controller running (PID: $(pgrep -f run_ryu_manager.py)). Logs at logs/controller.log"
    else
        echo "   -> Error starting Ryu controller. Check logs/controller.log"
        cat logs/controller.log
        exit 1
    fi
else
    echo "[Phase 2] Ryu controller is already running."
fi

# Number of trials (default: 1 for quick validation, or pass argument e.g. ./run_pipeline.sh 10 300)
TRIALS=${1:-1}
DURATION=${2:-60} # Default 60s per trial for quick validation; use 300s for full paper run

echo "[Phase 3 & 4] Running $TRIALS trial(s) (duration: ${DURATION}s each)..."
for i in $(seq 1 $TRIALS); do
    TRIAL_DIR=$(printf "trial_%02d" $i)
    echo "---------------------------------------------------------"
    echo "Starting Trial $i -> $TRIAL_DIR"
    echo "---------------------------------------------------------"
    if ! sudo python3 run_experiment.py --attacker h4 --victim h11 --duration $DURATION --trial-dir $TRIAL_DIR; then
        echo "WARNING: $TRIAL_DIR failed after network cleanup; continuing with remaining trials."
        continue
    fi

    # Use the decision slice copied into this trial directory.
    DECISIONS_FILE="$TRIAL_DIR/decisions.jsonl"
    AVAILABILITY_FILE=$(ls -t $TRIAL_DIR/availability_*.jsonl 2>/dev/null | head -n 1)

    if [ -s "$DECISIONS_FILE" ] && [ -n "$AVAILABILITY_FILE" ]; then
        echo "Computing real metrics for $TRIAL_DIR..."
        python3 metrics_from_logs.py \
            --decisions "$DECISIONS_FILE" \
            --ground-truth "$TRIAL_DIR/ground_truth.json" \
            --availability "$AVAILABILITY_FILE" \
            --out "$TRIAL_DIR/real_metrics_summary.json"
    fi
done

# Package only complete, current trial artifacts for reproducibility.
TRIAL_DIRS=""
for i in $(seq 1 "$TRIALS"); do
    trial_dir=$(printf "trial_%02d" "$i")
    if [ -s "$trial_dir/decisions.jsonl" ] && \
       [ -s "$trial_dir/ground_truth.json" ] && \
       [ -s "$trial_dir/real_metrics_summary.json" ]; then
        TRIAL_DIRS="$TRIAL_DIRS $trial_dir"
    fi
done
if [ -n "$TRIAL_DIRS" ]; then
    python3 build_dataset.py --trials $TRIAL_DIRS --output dataset \
        --baselines metrics/baselines_reference.json \
        --reference-metrics metrics/metrics_summary.json
fi

# Phase 5: Generate report if trials completed
echo "[Phase 5] Generating Results Report..."
if [ -n "$TRIAL_DIRS" ]; then
    python3 generate_results_report.py \
        --model-metrics model_metrics.json \
        --trials $TRIAL_DIRS \
        --decisions-dir logs \
        --baselines metrics/baselines_reference.json \
        --reference-metrics metrics/metrics_summary.json \
        --out Results_Report.docx || true
    echo "========================================================="
    echo " Pipeline Completed Successfully!"
    echo " Results Report: Results_Report.docx"
    echo "========================================================="
fi
