# =========================================
# 🐍 Base image (Linux-based, lightweight)
# =========================================
FROM python:3.11-slim

WORKDIR /app

# =========================================
# ⚙️ Install system dependencies for building packages
# =========================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    linux-headers-amd64 \
    && rm -rf /var/lib/apt/lists/*

# =========================================
# 📦 Python dependencies
# =========================================
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# =========================================
# 📂 Copy project
# =========================================
COPY . .

ENV PYTHONUNBUFFERED=1
ENV PYTHONIOENCODING=UTF-8

CMD ["python", "monitor.py"]
