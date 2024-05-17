# HoneyPot_with_SIEM-integration

This project is a simple honeypot implementation in Python with integrated geolocation tracking and SIEM (Security Information and Event Management) integration.

## Overview

A honeypot is a security mechanism set up to detect, deflect, or counteract attempts at unauthorized use of information systems. This honeypot is designed to simulate vulnerable services, such as SSH, HTTP, and FTP, to lure attackers and gather information about their activities.

## Features

- Simulated SSH, HTTP, and FTP services to attract potential attackers.
- Geolocation tracking to identify the geographical origin of attackers.
- Integration with Discord webhook for real-time alerts.
- Easy integration with SIEM solutions for centralized log management and analysis.

## Requirements

- Python 3.x
- GeoLite2 City database (downloadable from [MaxMind](https://dev.maxmind.com/geoip/geoip2/geolite2/))

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/HoneyPot_with_SIEM-integration.git
