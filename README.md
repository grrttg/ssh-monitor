
# SSH Log Monitoring & Analysis Script

## Overview
This script automates the analysis of SSH authentication logs to detect and report suspicious activity while providing flexible, user-configurable thresholds and safeguards against excessive alerts or unnecessary API calls.

---

## Key Features
- **Brute-Force Attack Pattern Detection**:
    - Repeated failed login attempts exceeding a user-defined threshold.
    - Bursts of failed login attempts within a configurable time window.
- **IP Reputation Analysis**:
    - Integrates with AbuseIPDB to assess the risk level of IP addresses involved in suspicious activity.
    - Avoids excessive API calls by:
        - Automatically skipping whitelisted IPs.
        - Prioritizing blacklisted IPs for immediate flagging without API lookups.
    - Allows users to configure reputation score thresholds to tailor the sensitivity of IP reputation checks.
- **Alert Management**:
    - Generates concise and structured JSON alerts with details such as timestamps, severity levels, and raw log lines.
    - Balances between comprehensiveness and efficiency to ensure actionable insights without overwhelming noise.
- **Secure and Flexible Configuration**:
    - Stores API keys securely in a .env file.
    - Customizable settings via a config.ini file, including:
        - Log file path.
        - Detection thresholds.
        - Whitelists and blacklists for fine-tuned control over IP handling.

---

## Usage

### Requirements
- Python 3.8 or higher
- Install dependencies: pip install -r requirements.txt
  
