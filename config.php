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
