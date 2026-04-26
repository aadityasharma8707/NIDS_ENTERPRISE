import subprocess
import time
import sys
import os

def check_docker():
    print("Checking if Docker containers are running...")
    try:
        result = subprocess.run(['docker', 'ps'], capture_output=True, text=True)
        if 'nids-kafka' not in result.stdout or 'nids-postgres' not in result.stdout:
            print("Starting Docker containers...")
            subprocess.run(['docker', 'compose', 'up', '-d'])
            time.sleep(5)  # Wait for containers to spin up
        else:
            print("Docker containers are already running.")
    except Exception as e:
        print(f"Warning: Could not check Docker status: {e}")

def main():
    check_docker()
    
    print("\nLaunching spark_consumer.py in the background...")
    # Use Popen to run in background
    consumer_process = subprocess.Popen([sys.executable, 'spark_consumer.py'])
    
    print("Launching Streamlit dashboard...\n")
    try:
        # Launch Streamlit. It will automatically open a browser window.
        subprocess.run([sys.executable, '-m', 'streamlit', 'run', 'dashboard.py'])
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        consumer_process.terminate()
        print("Consumer process terminated.")

if __name__ == '__main__':
    main()
