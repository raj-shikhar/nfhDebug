# Dockerfile
FROM python:3.12

WORKDIR /app

# Copy just the requirements.txt file first and install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt


# Copy the current directory contents into the container at /app
COPY . .

# Install dependencies from requirements.txt

# Install Firefox browser and download the recommended geckodriver version
RUN apt-get update && \
    apt-get install -y firefox-esr && \
    apt-get install -y wget && \
    wget https://github.com/mozilla/geckodriver/releases/download/v0.34.0/geckodriver-v0.34.0-linux64.tar.gz && \
    tar -xf geckodriver-v0.34.0-linux64.tar.gz && \
    chmod +x geckodriver && \
    mv geckodriver /usr/local/bin/

# Set the entry point to run the specific Python module
CMD ["python", "app.py"]
