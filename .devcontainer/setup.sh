#!/bin/bash
set -e

echo "========================================================="
echo " Setting up SDN Enterprise Experiment Environment"
echo "========================================================="

# Update package lists
sudo apt-get update

# Install networking tools, mininet, and pre-built Python science packages
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
    python3-pandas \
    python3-numpy \
    python3-sklearn \
    python3-matplotlib \
    gcc

# Install Python packages
sudo pip3 install --upgrade pip 2>/dev/null || true
sudo pip3 install eventlet==0.30.2
sudo pip3 install ryu python-docx joblib

# Start Open vSwitch service
sudo service openvswitch-switch start 2>/dev/null || true

# Pre-train the ML model
if [ -f "train_model.py" ]; then
    echo "Training initial model..."
    python3 train_model.py || true
fi

echo "========================================================="
echo " Environment setup completed!"
echo " Ready to run: ./run_pipeline.sh"
echo "========================================================="
