# Use a lightweight Python base image
FROM python:3.10-slim

# Install system dependencies required for PostgreSQL (psycopg2) and ML libraries
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all your NIDS-X project files into the container
COPY . .

# Expose the port Streamlit uses
EXPOSE 8501

# The ignition command to start the dashboard
CMD ["streamlit", "run", "dashboard.py", "--server.port", "8501", "--server.address", "0.0.0.0"]
