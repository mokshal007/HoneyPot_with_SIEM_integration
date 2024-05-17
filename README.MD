# HoneyPot_with_SIEM-integration

This project is a honeypot implementation in Python designed to attract and monitor potential attackers. It includes integrated geolocation tracking and integration with Splunk for centralized log management and analysis.

## Overview

A honeypot is a security mechanism set up to detect, deflect, or counteract attempts at unauthorized use of information systems. This honeypot simulates vulnerable services, such as SSH, HTTP, and FTP, to lure attackers and gather information about their activities. It includes geolocation tracking to identify the geographical origin of attackers and integration with Discord for real-time alerts. Additionally, it integrates with Splunk for centralized log management and analysis, enabling security teams to monitor and respond to security events effectively.

## Features

- Simulated SSH, HTTP, and FTP services to attract potential attackers.
- Geolocation tracking to identify the geographical origin of attackers.
- Integration with Discord webhook for real-time alerts.
- Integration with Splunk for centralized log management and analysis.

## Requirements

- Python 3.x
- GeoLite2 City database (downloadable from [MaxMind](https://dev.maxmind.com/geoip/geoip2/geolite2/))
- Splunk Universal Forwarder (for SIEM integration)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/mokshal007/HoneyPot_with_SIEM-integration.git
