FROM python:3.11-slim

# Install build tools
RUN apt-get update && apt-get install -y \
    cmake \
    gcc \
    g++ \
    make \
    libssl-dev \
    git \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

# Build liboqs from source
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cmake -S liboqs -B liboqs/build \
    -DOQS_DIST_BUILD=ON \
    -DBUILD_SHARED_LIBS=ON && \
    cmake --build liboqs/build --parallel 4 && \
    cmake --install liboqs/build && \
    rm -rf liboqs

# Set working directory
WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]
