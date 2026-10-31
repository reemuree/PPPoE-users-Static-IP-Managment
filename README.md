<p align="center">
  <b>A lightweight and professional IP allocation management dashboard for MikroTik ISP networks.</b>
</p>

<p align="center">
  Monitor PPPoE users, track static IP assignments, detect conflicts, and manage your IP address inventory from one centralized dashboard.
</p>

📌 Overview

MikroTik PPPoE IP Allocation Manager is a web-based dashboard developed for Internet Service Providers (ISPs) to simplify static IP allocation monitoring and management.

The application connects to MikroTik RouterOS through its API and collects information from PPPoE secrets, active sessions, and routing tables.

Instead of manually checking multiple RouterOS menus, administrators can view their IP allocation status, identify duplicate assignments, monitor available addresses, and manage their network inventory through a clean and responsive interface.

The application uses read-only RouterOS API access and does not modify router configurations.

✨ Key Features

Static IP Management — Track static IP addresses assigned to PPPoE users.

Automatic Conflict Detection — Identify duplicate IP assignments and IP collisions involving active sessions.

IP Pool Monitoring — Expand administrator-selected CIDR blocks and monitor available IP addresses.

Free & Assigned IP Tracking — Get a clear overview of free, assigned, and reserved IP addresses.

Live PPPoE Monitoring — Compare active PPPoE sessions with configured PPP secrets.

Read-Only Router Integration — Retrieve network information without changing router configurations.

Real-Time Dashboard — Monitor network IP allocation statistics.

Interactive Charts — Visualize IP allocation using Doughnut charts.

Searchable Inventory — Search and sort IP allocation records.

Quick Filters — Filter IP addresses and allocation statuses from the sidebar.

CSV Export — Export IP inventory data for external analysis.

Background Synchronization — Automatically synchronize router data every 30 seconds.

Responsive Interface — Access the dashboard from desktop and mobile devices.

🖥️ Dashboard Preview

<!-- Add your dashboard screenshot here -->

<!-- Example: ![Dashboard Preview](screenshots/dashboard.png) -->

🛠️ Technology Stack

Component

Technology

Backend

Python 3

Web Framework

Flask

Router API

librouteros

Database

SQLite

Frontend

HTML5, CSS3

JavaScript

Vanilla JavaScript (ES6+)

Charts

Chart.js

Data Export

CSV

No JavaScript frameworks or Node.js required.

📋 Prerequisites

Before installing, make sure you have:

Ubuntu Server 22.04 / 24.04 LTS or Windows

Python 3.8 or higher

MikroTik RouterOS v6 or v7

RouterOS API access enabled

A dedicated MikroTik API user with read-only permissions

Network connectivity between the application server and MikroTik router

🚀 Installation Guide

1. Install System Dependencies

For Ubuntu Server:

sudo apt update
sudo apt install -y python3 python3-venv python3-pip git

2. Clone the Repository

git clone YOUR_GITHUB_REPOSITORY_URL
cd YOUR_PROJECT_FOLDER

Replace the repository URL and folder name with your actual project details.

3. Create a Python Virtual Environment

python3 -m venv venv
source venv/bin/activate

4. Install Python Dependencies

pip install -r requirements.txt

5. Configure MikroTik API Access

Enable API access on your MikroTik router:

/ip service enable api

Create a dedicated read-only user and assign it to a group with appropriate read permissions.

Example:

/user group add name=ip-manager-read policy=read,api
/user add name=ipmanager group=ip-manager-read password=YOUR_STRONG_PASSWORD

For production environments, restrict API access to the application server's IP address using MikroTik firewall rules. Do not expose the API service publicly.

6. Configure the Application

Update the router connection settings according to your project's configuration method.

You will need:

MikroTik Router IP address

API Port

API Username

API Password

Keep credentials private. Never commit real router passwords or sensitive configuration files to GitHub.

7. Run the Application

Use your project's configured Flask entry point. For example:

python3 app.py

Open the dashboard in your browser using the address and port configured by the application.

🔐 Security

Security is important when managing ISP network infrastructure.

Use a dedicated RouterOS API account.

Grant only the permissions required for reading network information.

Restrict API access to trusted IP addresses.

Use strong passwords.

Keep router credentials out of source code and public repositories.

Use HTTPS when exposing the dashboard beyond a trusted local network.

💾 Data & Synchronization

The application uses SQLite for storing application settings.

Router information is retrieved through the MikroTik API and synchronized in the background at 30-second intervals.

The dashboard provides an updated view of IP allocation based on the collected router information.

🎯 Designed For

Internet Service Providers (ISPs)

MikroTik Network Administrators

PPPoE Network Operators

Network Engineers

ISP Technical Support Teams

🗺️ Future Improvements

Possible future enhancements:

Multiple MikroTik router support

IP allocation history

Advanced IP conflict reports

User activity logs

IP reservation management

Advanced network analytics

❤️ Support the Developer

If this project helps you manage your ISP network, you can support its development through Chabondhu.

<p align="center">
  <a href="https://chabondhu.com/reemuree">
    <img src="https://img.shields.io/badge/Support%20Development-Donate%20via%20Chabondhu-ff69b4?style=for-the-badge" alt="Donate via Chabondhu" />
  </a>
</p>

<p align="center">
  <a href="https://chabondhu.com/reemuree">Donate via Chabondhu</a>
</p>

Every contribution is appreciated and helps support future development. ❤️


📄 License

Specify your preferred open-source license in the repository. If no license file is included, all rights remain with the copyright holder by default.

<p align="center">
  Developed with ❤️ for MikroTik ISP Network Administrators.
</p>

<p align="center">
  <b>MikroTik PPPoE IP Allocation Manager</b>
</p>
