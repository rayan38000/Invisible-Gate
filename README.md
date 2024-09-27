# 🛡 Invisible Gate
Invisible Gate is an advanced website protection system designed to detect and block malicious bots without disrupting the user experience. Unlike traditional captchas, Invisible Gate works passively, discreetly analyzing user behavior, HTTP headers, IP address and other indicators of suspicious traffic. This invisible security shield automatically identifies fraudulent activities such as the use of proxies, automated requests, and non-compliant browsers, ensuring a smooth and secure browsing experience for legitimate users while keeping potential threats at bay.


---

<br>

## 🚀 Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/rayan38000/Invisible-Gate.git
    ```

2. **Place the configuration file in the root directory of your project.**

3. **Ensure that your PHP server has the appropriate permissions to read the configuration file.**

<br>

## ✅ Features

### 🔍 Request Analysis

- **HTTP Header and User-Agent Verification**  
  Analyzes HTTP headers and user-agent to detect suspicious and potentially malicious behaviors.

- **API Lookup for IP Address**  
  Queries an external API to obtain additional information about the IP address, aiming to identify potential threats.
<br>

### 📊 Behavior Monitoring

- **Request Tracking and User-Agent Changes**  
  Monitors all user requests and user-agent changes to detect abnormal patterns.

- **Detection of Unusual Behaviors**  
  Identifies unusual behaviors, such as frequent refreshes or a high volume of requests, which may indicate an attack or fraud attempt.
<br>

### 🚫 Suspicious IP Detection

- **Comparison with Local Blacklist**  
  Compares IP addresses against an internal blacklist to detect IPs known for malicious or suspicious activities.

- **Proxy and VPN Detection**  
  Detects the use of proxies or VPNs to mask the real identity of users, thereby identifying attempts to bypass protections.
<br>

### 🍯 Honey pot

- **Invisible Form for Bots**  
  Implements a hidden form that only bots will attempt to submit, allowing effective identification and blocking of bots.

<br>

## 🛠️ Configuration

Here’s how to customize the parameters of our anti-bot protection to fit your specific needs.

The `config.php` configuration file looks like this:

```php
<?php

// 🛡️ Activate Anti-Bot protection
$antibot = True;

// 🛠️ Configuring Anti-Bot Protection
$checkingIP = True;
$checkingNav = True;
$checkingHeader = True;
$debugMode = True;
$honeypot = True;
$redirection = 'https://google.com';

// 🕵️ Setting up User Behavior Monitoring
$userBehaviorMonitoring = True; // Enables/disables user behavior monitoring
$suspiciousActionNumber = 2; // Number of suspicious action laws the user can violate before receiving an ip ban
$timingBetwenRequests = 1; // Cooldown tolerated between 2 requests in seconds
$useragentSwitcherDetector = True; // Detects user agent rotation
$ipSwitcherDetector = True; // Detects proxy rotation
$exceedRequests = 100 // Defines a 5-minute query limit

?>
```

### Configuration Parameters

| **Parameter**                   | **Description**                                                                                         | **Default Value**     |
|---------------------------------|---------------------------------------------------------------------------------------------------------|-----------------------|
| `$antibot`                      | Activates or deactivates anti-bot protection.                                                           | `true`                |
| `$checkingIP`                   | Checks if the IP address does not belong to a suspicious organization/company/service                   | `true`                |
| `$checkingNav`                  | Checks user agents (User-Agent).                                                                        | `true`                |
| `$checkingHeader`               | Checks HTTP headers to detect proxies.                                                                  | `true`                |
| `$debugMode`                    | Enables debug mode for log messages instead of redirections.                                            | `true`                |
| `$honeypot`                     | URL to which suspicious users will be redirected.                                                       | `'https://google.com'`|
| `$redirection`                  | URL to which suspicious users will be redirected.                                                       | `'https://google.com'`|
| `$userBehaviorMonitoring`       | Enables user behavior monitoring.                                                                       | `true`                |
| `$suspiciousActionNumber`       | Number of suspicious actions allowed before a session ban.                                              | `2`                   |
| `$timingBetwenRequests`         | Allowed delay between two requests (in seconds).                                                        | `1`                   |
| `$useragentSwitcherDetector`    | Detects frequent user agent changes.                                                                    | `true`                |
| `$ipSwitcherDetector`           | Detects frequent IP address changes.                                                                    | `true`                |
| `$exceedRequests`               | Limit on the number of requests allowed in 5 minutes.                                                   | `100`                 |



## 💡 Usage

After configuring the `config.php` file, you need to upload 3 files to the root of your website: `antibot.php`, `config.php`, and `honeypot.php` (the `resetSession.php` file is optional; it allows you to lift a session ban).

To protect your pages with the script, simply add this line at the very beginning of your pages (as done in the `index.php` file):
```php
<?php include 'antibot.php'; ?>
```
---

