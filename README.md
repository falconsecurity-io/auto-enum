# Hack The Box Automation Scripts

This repository contains a collection of Bash scripts designed to automate the setup of virtual machines (VMs) and the enumeration of machines on [Hack The Box](https://www.hackthebox.eu/). The goal is to streamline the process of configuring your hacking environment and performing initial reconnaissance on target machines.

## Purpose

The scripts in this repository are intended to:
- **Automate VM Setup:** Quickly configure Pwnbox or VM with the necessary setup and settings for penetration testing.
- **Enumerate Machines:** Automate the initial reconnaissance phase by scanning and gathering information about Hack The Box machines.
- **Save Time:** Reduce the manual overhead involved in setting up your environment and performing repetitive tasks.
- **Enhance Productivity:** Allow you to focus on analyzing vulnerabilities and exploiting targets rather than spending time on setup.

## Features

- **Automated Environment Configuration:** Easily set up VMs with all required dependencies and tools.
- **Enumeration Scripts:** Scripts that handle network scanning, port enumeration, and service identification.
- **Customizable Workflow:** Easily modify and extend scripts to fit your unique workflow and Hack The Box challenges.

## Getting Started

### Prerequisites

- A Unix-like operating system (Linux, macOS, or WSL on Windows)
- [Bash](https://www.gnu.org/software/bash/) shell
- [Xdotool](https://github.com/jordansissel/xdotool) automation
- Basic knowledge of command-line operations

### Installation

#### **Clone the repository**
   ```bash
   mkdir ~/Scripts
   cd ~/Scripts
   git clone https://github.com/falconsecurity-io/auto-enum.git
   chmod +x ~/Scripts/auto-enum/*.sh
   ```
#### **Set up aliases**
   ```bash
   cat ~/Scripts/auto-enum/aliases.txt >> ~/.bash_aliases
   source ~/.bashrc
   ```
#### **Install dependencies**
```bash
sudo apt-get install xdotool -y
sudo apt-get install tree -y
```
### Usage
#### To set up terminals and desktop for hacking
   ```bash
   setup htb main
   ```
#### To start automated initial enumeration
   ```bash
   enum main lame yes 10.129.0.1
   ```
#### Query NTLM.pw for NLTM hash
  ```bash
  ntlmpw nt/lm/sha256 hashes_nt
  ```
