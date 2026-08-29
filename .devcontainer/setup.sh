#!/bin/bash
set -e

echo "========================================================="
echo " Setting up SDN Enterprise Experiment Environment"
echo "========================================================="

# Update package lists
sudo apt-get update

# Install networking tools & mininet
sudo apt-get install -y --no-install-recommends \
    mininet \
    openvswitch-switch \
    openvswitch-common \
    iperf \
    iperf3 \
    hping3 \
    netcat-openbsd \
    tcpdump \
    psmisc \
    python3-pip \
    python3-setuptools \
    python3-dev \
    gcc

# Install Python packages
pip3 install --upgrade pip
pip3 install eventlet==0.30.2
pip3 install ryu scikit-learn numpy pandas joblib matplotlib

# Start Open vSwitch service
sudo service openvswitch-switch start || true

# Pre-train the ML model
if [ -f "train_model.py" ]; then
    echo "Training initial model..."
    python3 train_model.py || true
fi

echo "========================================================="
echo " Environment setup completed! You are ready to run:"
echo " 1. Start controller: sudo ryu-manager enterprise_security_controller_v2.py"
echo " 2. In 2nd terminal: sudo python3 run_experiment.py --attacker h13 --victim h11 --duration 300 --trial-dir trial_01"
echo "========================================================="
