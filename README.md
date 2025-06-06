# SYE Nmap Tool

A powerful and user-friendly Bash-based Nmap wrapper tool with 10 categories and 100 commands for comprehensive network scanning and security testing.

## Features

- Colorful and clear menu interface with ASCII art and emoji
- 10 main categories covering various Nmap scan types and techniques
- Each category contains 10 detailed options (total 100 commands)
- Log system with timestamped files
- Checks for Nmap installation and guides installation if missing
- Easy to use for both beginners and advanced users

## Installation

Make sure you have `nmap` installed on your system.

For Debian/Ubuntu:

```bash
sudo apt update && sudo apt install nmap
git clone https://github.com/syesociety/nmapsye-advanced
cd sye-nmap-tool
chmod +x sye-nmap.sh
./sye-nmap.sh
