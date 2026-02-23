[render-build.sh](https://github.com/user-attachments/files/25474132/render-build.sh)
#!/bin/bash
# Render Build Script for Quantum-Safe Encryption Backend
# This installs liboqs system library before Python packages

set -e  # Exit on error

echo "========================================="
echo "Installing liboqs system library..."
echo "========================================="

# Update package list
apt-get update

# Install liboqs development files
apt-get install -y liboqs-dev

echo "✅ liboqs installed successfully"

echo "========================================="
echo "Installing Python dependencies..."
echo "========================================="

# Install Python packages
pip install --upgrade pip
pip install -r requirements.txt

echo "✅ All dependencies installed"
echo "========================================="
echo "Build complete!"
echo "========================================="
