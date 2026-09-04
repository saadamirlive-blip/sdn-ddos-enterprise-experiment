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

# Phase 1: Train model if not already trained
if [ ! -f "model.pkl" ] || [ ! -f "scaler.pkl" ] || [ ! -f "model_metrics.json" ]; then
    echo "[Phase 1] Training ML Model..."
    python3 train_model.py
else
    echo "[Phase 1] ML Model already trained (model.pkl, scaler.pkl, model_metrics.json exist)."
fi

# Phase 2: Start Ryu controller in background if not running
mkdir -p logs
if ! pgrep -f "ryu-manager" > /dev/null; then
    echo "[Phase 2] Starting Ryu Security Controller in background..."
    sudo ryu-manager enterprise_security_controller_v2.py > logs/controller.log 2>&1 &
    sleep 5
    if pgrep -f "ryu-manager" > /dev/null; then
        echo "   -> Ryu Controller running (PID: $(pgrep -f ryu-manager)). Logs at logs/controller.log"
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
    sudo python3 run_experiment.py --attacker h4 --victim h11 --duration $DURATION --trial-dir $TRIAL_DIR

    # Find latest decisions and availability files
    DECISIONS_FILE=$(ls -t logs/decisions_*.jsonl 2>/dev/null | head -n 1)
    AVAILABILITY_FILE=$(ls -t $TRIAL_DIR/availability_*.jsonl 2>/dev/null | head -n 1)

    if [ -n "$DECISIONS_FILE" ] && [ -n "$AVAILABILITY_FILE" ]; then
        echo "Computing real metrics for $TRIAL_DIR..."
        python3 metrics_from_logs.py \
            --decisions "$DECISIONS_FILE" \
            --ground-truth "$TRIAL_DIR/ground_truth.json" \
            --availability "$AVAILABILITY_FILE" \
            --out "$TRIAL_DIR/real_metrics_summary.json"
    fi
done

# Phase 5: Generate report if trials completed
echo "[Phase 5] Generating Results Report..."
TRIAL_DIRS=$(ls -d trial_* 2>/dev/null | tr '\n' ' ')
if [ -n "$TRIAL_DIRS" ]; then
    python3 generate_results_report.py \
        --model-metrics model_metrics.json \
        --trials $TRIAL_DIRS \
        --decisions-dir logs \
        --out Results_Report.docx || true
    echo "========================================================="
    echo " Pipeline Completed Successfully!"
    echo " Results Report: Results_Report.docx"
    echo "========================================================="
fi
