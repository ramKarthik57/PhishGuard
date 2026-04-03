# Use latest Python 3.12 slim image
FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends gcc build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels gunicorn

# Final Stage
FROM python:3.12-slim

WORKDIR /app

# Create a non-root user
RUN addgroup --system phishguard && adduser --system --group phishguard

# Copy the pre-built wheels and install them
COPY --from=builder /app/wheels /wheels
RUN pip install --no-cache /wheels/*

# Copy application code
COPY . .

# Ensure artifacts and logs directories exist and are writable
RUN mkdir -p artifacts logs && \
    chown -R phishguard:phishguard /app

USER phishguard

# Expose the application port
EXPOSE 5000

# Run with Gunicorn instead of the Flask dev server
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "4", "--threads", "2", "app:app"]
