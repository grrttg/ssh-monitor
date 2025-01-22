# writeup.md

**Project Title:** SSH Log Monitoring and IP Reputation Analysis

**Author:** C. Garrett Gue

**Date:** January 21, 2025

**1. Introduction**

Monitoring SSH authentication logs is one way to identify unauthorized access attempts and potential security breaches. This project presents a Python script designed to analyze SSH logs for suspicious activities, such as repeated failed login attempts and rapid succession of failures within a short time frame. Additionally, it integrates with the AbuseIPDB API to assess the reputation of IP addresses involved in these events, enhancing the ability to detect and respond to malicious actors.

**Objectives**

- Develop a Python script to parse and analyze SSH authentication logs.
- Identify patterns indicative of potential security threats, including:
    - Multiple consecutive failed login attempts.
    - Bursts of failed attempts within a defined time window.
- Integrate with the AbuseIPDB API to evaluate the reputation of IP addresses associated with suspicious activities.
- Generate alerts for detected anomalies and log them for further analysis.
- Do all of this with **secure coding practices**, e.g.:
    - Secure API Key storage in `.env`
    - Don’t expose sensitive IP addresses (RFC 5737 in samples, use `.gitignore` correctly)
    - Obfuscation and “Privacy Mode” when using LLM assistance.

**Features**

- **Log Parsing:** Reads and parses SSH authentication logs to extract relevant events, including failed and successful login attempts.
- **Pattern Detection:**
    - Detects IP addresses exceeding a threshold of consecutive failed login attempts.
    - Identifies bursts of failed login attempts from the same IP within a specified time window.
- **IP Reputation Check:** Interfaces with the AbuseIPDB API to retrieve the abuse confidence score of IP addresses involved in suspicious activities.
- **Alert Generation:** Compiles detected anomalies into structured alerts, including details such as the source IP, type of alert, severity, and related log entries.
- **Configuration Flexibility:** Utilizes a configuration file (`config.ini`) and environment variables for customizable settings, including thresholds, time windows, and file paths.

**Implementation Details**

- **Programming Language:** Python 3.x
- **Libraries Used:**
    - `re`: For regular expression operations to parse log entries.
    - `sys`: For command-line argument handling.
    - `json`: For formatting alerts in JSON.
    - `os`: For environment variable access.
    - `ipaddress`: For IP address manipulations.
    - `requests`: For HTTP requests to the AbuseIPDB API.
    - `datetime` and `timedelta`: For timestamp parsing and time window calculations.
    - `dataclasses`: For structured storage of login events.
    - `configparser`: For reading configuration settings.
    - `dotenv`: For loading environment variables from a `.env` file.
- **Configuration:**
    - Settings are defined in a `config.ini` file, including log file paths, thresholds for detection, and alert logging preferences.
    - The AbuseIPDB API key is stored securely in a `.env` file and loaded at runtime.

**Usage Instructions**

For detailed usage instructions, please refer to the `README.md` file in the project repo.

**Sample Alert Output**

```json
{
  "timestamp": "2025-01-21T14:35:00",
  "alert_type": "RepeatedFailures",
  "source_ip": "192.168.1.100",
  "failed_count": 5,
  "severity": "MEDIUM",
  "raw_logs": [
    "Failed password for invalid user admin from 192.168.1.100 port 22 ssh2",
    "Failed password for invalid user admin from 192.168.1.100 port 22 ssh2",
    "Failed password for invalid user admin from 192.168.1.100 port 22 ssh2",
    "Failed password for invalid user admin from 192.168.1.100 port 22 ssh2",
    "Failed password for invalid user admin from 192.168.1.100 port 22 ssh2"
  ]
}

```

**Challenges Encountered**

- **Log Format Variability:** SSH log formats can vary across different systems and configurations. I originally started writing this script on my Linux machine and it worked great with my `/var/log/auth.log` , but may need to be reconfigured for different systems.
- **API Rate Limiting:** I tried to mitigate this a bit without going too far down the rabbit hole. No IP address caching here. I did start to try resolving and validating IPs before sending to API, but for the purposes of this project, basic error handling and whitelisting/blacklisting will have to suffice.
- **IP Address Parsing:** Accurately extracting IP addresses from log entries necessitates robust regular expressions to account for various log formats and potential anomalies. I truly enjoy and embrace the **secure use of LLMs** to teach me and help navigate these kinds of hurdles.

**Future Enhancements**

- **Machine Learning Integration:** I want to be able to identify more complex patterns and explore what is now a basic requirement for real tools like this.
- **Reducing API calls:** There’s a lot more that could be done here, I think. Caching, rate-limiting logic, etc. More of an ongoing thing, but again…. real tools already exist.
- **Real-time Monitoring:** Extend the script to monitor SSH logs in real-time.
- **Advanced Alerting:** Integrate alert notifications with slack or email.
- **Comprehensive Reporting:** Develop detailed reports summarizing detected threats, historical trends, and actionable recommendations for security improvements.

**Conclusion**

This project provides a lightweight yet powerful tool for monitoring SSH authentication logs and identifying potential security threats. By combining log analysis with IP reputation checks using the AbuseIPDB API, it bridges the gap between traditional log monitoring and proactive threat intelligence. While it’s not a full-fledged intrusion detection system, its modular design makes it adaptable and easy to integrate into broader security workflows.
