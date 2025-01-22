# SSH Log Monitoring & Analysis Script

## Overview

This script analyzes SSH authentication logs to detect suspicious activity. It supports customizable thresholds, minimizing excessive alerts and unnecessary API calls.

---

## Key Features

- **Brute-Force Attack Pattern Detection**:
    - **Sequential Failure Monitoring:** Identifies potential attacks by detecting sequences of repeated failed login attempts from a single IP address that exceed a configurable threshold.
    - **Time-Window Analysis:** Detects suspicious bursts of failed login attempts occurring within a user-defined time window, indicative of automated attacks.
- **IP Reputation Analysis**:
    - Integrates with [AbuseIPDB](https://www.abuseipdb.com/) to assess the risk level of IP addresses involved in suspicious activity.
    - Avoids excessive API calls by:
        - Automatically skipping whitelisted IPs.
        - Prioritizing blacklisted IPs for immediate flagging without API lookups.
        - Allows users to configure reputation score thresholds to tailor alert sensitivity.
- **Alert Management**:
    - Generates concise and structured JSON alerts with details such as timestamps, severity levels, and raw log lines.
    - Balances between comprehensiveness and efficiency to ensure actionable insights without overwhelming noise.
- **Secure and Flexible Configuration**:
    - Stores API keys securely in a `.env` file.
    - Customizable settings via a `config.ini` file, including:
        - Log file path.
        - Detection thresholds.
        - Whitelists and blacklists for fine-tuned control over IP handling.

---

## Usage

### Requirements

- Python 3.8 or higher
- Install dependencies: `pip install -r requirements.txt`

### Setup

1. **API Key:**
    - Obtain an API key from [AbuseIPDB](https://www.abuseipdb.com/).
    - Create a file named `.env` in the project's root directory.
    - Add the following line to `.env`, replacing `YOUR_API_KEY_HERE` with your actual key:
        
        ```
        ABUSEIPDB_API_KEY=YOUR_API_KEY_HERE
        
        ```
        
2. **Configuration (Optional):**
    - Create a `config.ini` file in the project's root directory.
    - You can customize settings such as log file path, thresholds, whitelist, and blacklist. See the `config.ini.example` file (or refer to the "Configuration Options" section below) for available options and their default values.
3. **Run:**
    
    ```bash
    python ssh_monitor.py
    
    ```
    

## Sample Log Files

This project includes sample log files in the `sample_logs/` directory to demonstrate various scenarios and alert triggers. **These files use IP addresses from RFC 5737 (TEST-NET documentation addresses) for security and to avoid conflicts. These addresses will not trigger reputation alerts.**

You can test the script with these sample logs using the following command:

```json
python ssh_monitor.py <path/to/sample.log>
```

For example:

```json
python ssh_monitor.py sample_logs/repeated_failures.log
```

### Testing Reputation Checks with Real IPs

The `sample_logs/reputation_check.log` file specifically demonstrates how the script handles IP reputation checks. It currently uses a safe TEST-NET IP address.

**To test with a real IP that has a high AbuseIPDB score:**

1. **Find a Real IP:** Search on [AbuseIPDB](https://www.abuseipdb.com/) to find a reported IP address with a high confidence score (e.g., 100%).
2. **Modify the Log File:** Carefully replace the TEST-NET IP address in `sample_logs/reputation_check.log` with the real IP address you found.
3. **Run the Script:**
    
    ```json
    python ssh_monitor.py sample_logs/reputation_check.log
    ```
    

**Caution:** When using real IP addresses, be mindful of privacy and ethical considerations. Only use IPs that are publicly reported on AbuseIPDB and avoid targeting any specific individual or system. The purpose of this test is to demonstrate the script's functionality, not to conduct any unauthorized security testing.