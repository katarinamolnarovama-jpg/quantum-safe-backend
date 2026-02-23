FROM python:3.11-slim
RUN apt-get update && apt-get install -y cmake gcc g++ make libssl-dev git ninja-build python3-dev && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && cmake -S liboqs -B liboqs/build -DOQS_DIST_BUILD=ON -DBUILD_SHARED_LIBS=ON && cmake --build liboqs/build --parallel 2 && cmake --install liboqs/build && rm -rf liboqs
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git && pip install ./liboqs-python && rm -rf liboqs-python
WORKDIR /app
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt
COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]
