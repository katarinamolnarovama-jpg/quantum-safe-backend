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
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs from source
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cmake -S liboqs -B liboqs/build \
    -DOQS_DIST_BUILD=ON \
    -DBUILD_SHARED_LIBS=ON && \
    cmake --build liboqs/build --parallel 2 && \
    cmake --install liboqs/build && \
    rm -rf liboqs

# Install liboqs-python wrapper from GitHub
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git && \
    pip install ./liboqs-python && \
    rm -rf liboqs-python

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]
```

2. Click **"Commit changes"**

---

## Also fix requirements.txt

Remove `liboqs-python==0.8.0` since we install it via Dockerfile now:
```
fastapi==0.104.1
uvicorn[standard]==0.24.0
python-multipart==0.0.6
asyncpg==0.29.0
cryptography==41.0.7
pyjwt==2.8.0
passlib[bcrypt]==1.7.4
pydantic[email]==2.5.0
python-jose[cryptography]==3.3.0
