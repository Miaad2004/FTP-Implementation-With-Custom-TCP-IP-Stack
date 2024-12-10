#!/bin/bash

# Define variables
SERVER_PATH="./"
VENV_PATH="$SERVER_PATH/venv"
REQUIREMENTS_FILE="$SERVER_PATH/requirements.txt"
SERVER_SCRIPT="$SERVER_PATH/start_server.py"
MIN_PYTHON_VERSION="3.10"

# Function to check Python version
check_python_version() {
    PYTHON_VERSION=$(python3.13 --version 2>&1)
    if [[ $PYTHON_VERSION =~ Python\ ([0-9]+\.[0-9]+\.[0-9]+) ]]; then
        CURRENT_VERSION=${BASH_REMATCH[1]}
        if [[ $(echo -e "$CURRENT_VERSION\n$MIN_PYTHON_VERSION" | sort -V | head -n1) != "$MIN_PYTHON_VERSION" ]]; then
            echo "Python $MIN_PYTHON_VERSION or higher is required. Current version: $CURRENT_VERSION"
            exit 1
        else
            echo "Python version $CURRENT_VERSION is sufficient."
        fi
    else
        echo "Unable to determine Python version."
        exit 1
    fi
}

# Function to create and activate virtual environment
setup_venv() {
    if [ ! -d "$VENV_PATH" ]; then
        echo "Setting up virtual environment..."
        python3.13 -m venv "$VENV_PATH"
        echo "Virtual environment setup complete."
    else
        echo "Virtual environment already exists."
    fi
    source "$VENV_PATH/bin/activate"
}

# Function to install Python packages
install_requirements() {
    echo "Installing Python packages from requirements.txt..."
    pip install -r "$REQUIREMENTS_FILE"
}

# Function to start the server
start_server() {
    echo "Starting the server..."
    python "$SERVER_SCRIPT"
}

# Main script execution
echo "Deploying the server..."
check_python_version
setup_venv
install_requirements
start_server
echo "Server deployed successfully."