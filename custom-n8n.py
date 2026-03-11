#!/usr/bin/env python3

# Libraries i used for this integration
import sys      # For getting command line arguments
import json     # For working with JSON data
import requests # For sending HTTP requests to n8n
import os       # For checking if files exist
import logging  # For writing to log files
from datetime import datetime  # For adding timestamps

# Logging Setup
# This configures where to write logs and what format to use
log_file = '/var/ossec/logs/integrations.log'
logging.basicConfig(
    filename=log_file,           # Log file path
    level=logging.INFO,           # Log level (INFO and above)
    format='%(asctime)s - n8n - %(levelname)s - %(message)s'  # Log format
)

def main():
    """
    This is the main function - everything starts here
    """
    
    # Log how many arguments we received
    # len(sys.argv) counts the arguments
    # -1 because the first argument (index 0) is the script name
    logging.info(f"Script called with {len(sys.argv)-1} arguments")
    
    # Log each argument so we can see them
    for i, arg in enumerate(sys.argv):
        logging.info(f"Arg {i}: '{arg}'")
    
    # Check if we have at least 2 arguments (alert file and webhook URL)
    # sys.argv[0] is the script name, so we need at least 3 total
    if len(sys.argv) < 3:
        logging.error("Not enough arguments - need alert file and webhook URL")
        sys.exit(1)  # Exit with error code 1
    
    # Get the alert file path (first argument after script name)
    alert_file = sys.argv[1]
    
    # Find the webhook URL - look for something starting with http
    webhook_url = None
    for arg in sys.argv:
        if arg.startswith('http://') or arg.startswith('https://'):
            webhook_url = arg
            logging.info(f"Found webhook URL: {webhook_url}")
            break
    
    # If we didn't find a URL, exit with error
    if not webhook_url:
        logging.error("No webhook URL found in arguments")
        sys.exit(1)
    
    # Check if the alert file actually exists
    if not os.path.exists(alert_file):
        logging.error(f"Alert file not found: {alert_file}")
        sys.exit(1)
    
    # Read the alert file
    try:
        with open(alert_file, 'r') as f:
            alert_json = f.read()
        logging.info(f"Successfully read alert file ({len(alert_json)} bytes)")
    except Exception as e:
        logging.error(f"Failed to read alert file: {str(e)}")
        sys.exit(1)
    
    # Parse the JSON alert into a Python dictionary
    try:
        alert = json.loads(alert_json)
        logging.info("Successfully parsed JSON alert")
    except Exception as e:
        logging.error(f"Failed to parse JSON: {str(e)}")
        sys.exit(1)
    
    # Add current timestamp to the alert
    alert['n8n_timestamp'] = datetime.utcnow().isoformat()
    
    # Send the alert to n8n
    try:
        # Make HTTP POST request to n8n webhook
        response = requests.post(
            webhook_url,
            json=alert,
            headers={'Content-Type': 'application/json'},
            timeout=10  # Wait max 10 seconds for response
        )
        
        # Check if request was successful (status codes 200-299)
        if response.status_code >= 200 and response.status_code < 300:
            logging.info(f"SUCCESS: Sent to n8n (Status: {response.status_code})")
            sys.exit(0)  # Exit with success code 0
        else:
            logging.error(f"FAILED: n8n returned status {response.status_code}")
            logging.error(f"Response: {response.text}")
            sys.exit(1)
            
    except requests.exceptions.ConnectionError:
        logging.error(f"ERROR: Cannot connect to {webhook_url}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"ERROR: {str(e)}")
        sys.exit(1)

# This tells Python to run the main() function when the script is executed
if __name__ == "__main__":
    main()
