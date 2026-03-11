#!/bin/bash
# e2b-template-setup.sh — Run during `e2b template build` to bake Silver into the template
# This pre-installs deps so postinit is fast (~5s vs ~60s)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "[silver-template] Pre-installing dependencies..."

apt-get update -qq
apt-get install -y -qq \
    clang llvm libbpf-dev bpftool \
    iproute2 nftables tcpdump \
    python3 python3-pip python3-venv \
    jq curl wget git autoconf automake libtool pkg-config \
    linux-tools-common

# Pre-build nDPI
cd /tmp
git clone --depth 1 https://github.com/ntop/nDPI.git 2>/dev/null || true
cd nDPI
./autogen.sh -q 2>/dev/null
./configure --prefix=/usr -q 2>/dev/null
make -j$(nproc) -s 2>/dev/null
make install -s 2>/dev/null
ldconfig
cd / && rm -rf /tmp/nDPI

# Pre-install Python packages
pip3 install -q pathway damo

# Create directory structure
mkdir -p /opt/silver/{bpf,cep,damon,configs}

# Download bootstrap script
curl -sSL https://raw.githubusercontent.com/pv-udpv/sliver-ebpf-silver/main/scripts/sbx-postinit.sh \
    -o /opt/silver/sbx-postinit.sh
chmod +x /opt/silver/sbx-postinit.sh

echo "[silver-template] Template setup complete"
echo "[silver-template] Add to e2b.toml: start_cmd = '/opt/silver/sbx-postinit.sh'"
