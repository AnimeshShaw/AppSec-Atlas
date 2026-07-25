# 05 - CTF Tooling and Environment Setup 🛠️

A well-configured environment is half the battle in a CTF. You need a dedicated Linux VM equipped with offensive tooling.

## 🐧 The Base Environment

While Kali Linux and Parrot OS come pre-installed with many tools, many top-tier CTF players prefer a clean **Ubuntu VM** and install only what they need.

### Essential Packages
```bash
sudo apt update
sudo apt install -y build-essential python3 python3-pip git wget curl gdb ncat docker.io docker-compose jq
```

---

## 💥 Pwn & Rev Tooling

### 1. Pwntools
The core library for exploit development.
```bash
pip3 install pwntools
```

### 2. GDB & Pwndbg
Vanilla GDB is difficult to use. Pwndbg adds a clean interface, memory visualization, and exploit-specific commands.
```bash
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

### 3. Ghidra
For reverse engineering. Requires Java.
```bash
sudo apt install default-jdk
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3_build/ghidra_10.3_PUBLIC_20230510.zip
unzip ghidra_10.3_PUBLIC_20230510.zip
./ghidraRun
```

---

## 🕸️ Web Tooling

### 1. Burp Suite Community Edition
The ultimate web proxy. Download from PortSwigger. Use it to intercept, modify, and replay HTTP requests.

### 2. Dirsearch / Gobuster
For directory and file fuzzing.
```bash
sudo apt install gobuster
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
```

---

## 🇨 CyberChef (Offline)

CyberChef (the "Cyber Swiss Army Knife") is a web app for decoding, encrypting, and parsing data. In some CTFs, internet access is restricted, so hosting it locally is crucial.

**Local Docker Deployment:**
```bash
docker run -d -p 8000:8000 mpepping/cyberchef
```
Access at `http://localhost:8000`.

---

## 🐳 Dockerized Challenge Deployment

Many CTF challenges are distributed as Docker containers so you can debug them locally before attacking the remote server.

**Example `docker-compose.yml` for a CTF Challenge:**
```yaml
version: '3.3'
services:
  web-challenge:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLAG=flag{local_docker_test_flag}
    read_only: true
```

**Running the Challenge:**
```bash
# Build and start the challenge
docker-compose up --build -d

# Check logs for errors
docker-compose logs -f

# Stop and remove the challenge
docker-compose down
```
