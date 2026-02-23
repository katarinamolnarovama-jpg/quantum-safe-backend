#!/bin/bash
set -e

echo "========================================="
echo "Installing liboqs system library..."
echo "========================================="

apt-get update
apt-get install -y liboqs-dev

echo "✅ liboqs installed successfully"

echo "========================================="
echo "Installing Python dependencies..."
echo "========================================="

pip install --upgrade pip
pip install -r requirements.txt

echo "✅ All dependencies installed"
echo "========================================="
echo "Build complete!"
echo "========================================="
