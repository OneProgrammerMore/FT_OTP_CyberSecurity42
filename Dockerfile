FROM python:3.10-slim

# Install system dependencies for GUI support
RUN apt-get update && apt-get install -y \
    python3-tk \
    libgl1-mesa-glx \
    libx11-6 \
    vim-common \
    libglib2.0-0
    
RUN apt-get update && apt-get install -y \
    qtbase5-dev \
    qtchooser \
    qt5-qmake \
    qtbase5-dev-tools \
    libqt5gui5 \
    libqt5widgets5 \
    libqt5core5a \
    libxkbcommon-x11-0

# Set the working directory
WORKDIR /app

# Copy requirements into the container
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application files
#COPY . .

# Command to run the application (adjust accordingly)
CMD ["python", "app.py"]
