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
    iputils-ping \
    tcpdump \
    psmisc \
    python3-pip \
    python3-setuptools \
    python3-dev \
    gcc

# Install Python packages
python3 -m pip install --upgrade pip
python3 -m pip install 'setuptools<58'
python3 -m pip install --no-build-isolation -r requirements.txt

# Start Open vSwitch service
sudo service openvswitch-switch start || true

# Pre-train the ML model
if [ -f "train_model.py" ]; then
    echo "Training initial model..."
    python3 train_model.py || true
fi

echo "========================================================="
echo " Environment setup completed!"
echo " Ready to run: ./run_pipeline.sh"
echo "========================================================="
