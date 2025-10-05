
# VISNET: an eBPF based Live Process Network Mapper

A full-stack observability tool that uses **eBPF** to capture system-level network events and visualizes them in real-time on a web-based dashboard.

[![Watch the demo](https://img.youtube.com/vi/uUEcFL2l7kk/hqdefault.jpg)](https://youtu.be/uUEcFL2l7kk)

---

## 📌 Introduction

Have you ever wondered what network connections are being made on your Linux machine when you run a command?
This project provides a **real-time window** into your system's network activity, showing you which processes are communicating with which IP addresses as it happens.

This tool hooks directly into the **Linux kernel** using **eBPF** to safely and efficiently capture process execution (exec, exit) and TCP connection (connect, accept, close) events. A **Go backend** processes these events and forwards them via **WebSockets** to a **JavaScript frontend**, which renders an **interactive, force-directed graph**.

The goal is to demonstrate the power of **eBPF** for runtime security and system monitoring, with **zero application-level instrumentation** required.

---

## ✨ Features

* **Real-Time Visualization**
  Watch processes and their network connections appear on the graph as they happen.

* **eBPF-Powered**
  Uses eBPF to safely and efficiently capture kernel events with minimal performance overhead.

* **Full-Stack Application**
  Built with C (eBPF), Go (backend), and JavaScript (frontend).

* **Connection Lifecycle Tracking**
  Visualizes TCP connection lifecycles, marking them as **inactive** when closed.

* **Manual Cleanup**
  A "Cleanup" button allows you to remove inactive nodes and edges for forensic analysis.

* **Dark Mode UI**
  A clean, modern, dark-themed user interface.

---

## ⚙️ How It Works

The application consists of three main components:

### 1. 🧬 eBPF Probe (`process_tracker.c`)

A small C program that runs in the kernel. It attaches to kprobes and tracepoints to capture:

* Process execution (exec, exit)
* TCP connection events (connect, accept, close)

It uses a **ring buffer** to pass data to user space efficiently.

### 2. ⚙️ Go Backend (`main.go`)

The user-space application that:

* Loads and attaches the eBPF program
* Listens for events from the kernel ring buffer
* Forwards events via **WebSocket** to connected clients

### 3. 💻 Frontend Dashboard (`index.html`, `main.js`)

A single-page web app that:

* Connects to the Go backend via WebSocket
* Displays an **interactive network graph** using [vis.js](https://visjs.org/)
* Allows user interaction like cleanup and hover details

---

## 🚀 Getting Started

These steps assume you're using a **Debian-based system** (Ubuntu or WSL2).

### ✅ Prerequisites

Install the following tools:

* Go (v1.18+)
* Clang/LLVM (v12+)
* Git
* Make & build-essential
* Python 3 (for the frontend HTTP server)
* Linux kernel headers
* `bpftool` and `libbpf-dev`

---

### 🛠️ Setup Instructions

#### 1. Install Dependencies

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libelf-dev libbpf-dev build-essential gcc-multilib
```

#### 2. Install bpftool

```bash
sudo apt-get install -y linux-tools-common linux-tools-generic
```

> ⚠️ WSL2 users: If you get a kernel mismatch error, you may need to compile `bpftool` manually from source.

#### 3. Generate Kernel Type Info (`vmlinux.h`)

```bash
mkdir -p headers
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./headers/vmlinux.h
```

#### 4. Build the Project

```bash
go generate    # Compiles eBPF code and generates Go bindings
go build       # Builds the backend Go server
```

#### 5. Mount tracefs (if not already)

```bash
sudo mount -t tracefs none /sys/kernel/tracing
```

---

## 🧪 Running the Application

Open **two terminals** in the project directory.

### Terminal 1: Run the Backend

```bash
sudo ./main
# Output: "eBPF probes attached. Forwarding events..."
#         "WebSocket server listening on :8080"
```

### Terminal 2: Serve the Frontend

```bash
python3 -m http.server 8000
# Output: "Serving HTTP on 0.0.0.0 port 8000..."
```

### View the Dashboard

Open your browser to:

```
http://localhost:8000
```

> 🐧 WSL2 Users: If `localhost` fails, use your WSL IP. Run `ip addr | grep eth0` to find it (e.g., `http://172.22.48.1:8000`).

---

## ⚡ Usage Example

With the dashboard open, try these in a **third terminal** to generate events:

### Update Package Lists

```bash
sudo apt-get update
```

### Download a Large File

```bash
curl -o /dev/null http://speed.tele2.net/100MB.zip
```

### Connect to a Public Database

```bash
mysql -h sql7.freesqldatabase.com -u sql7654321 -p
# Password: yE8g9h2Z*U
# Type `exit` to close the session and see the graph update
```

---

## 🗂️ Project Structure

```
.
├── headers/
│   └── vmlinux.h          # Auto-generated kernel type info
├── process_tracker.c      # eBPF C code (kernel side)
├── gen.go                 # `go:generate` glue logic
├── main.go                # Go backend (event forwarder)
├── index.html             # Frontend HTML
├── style.css              # UI styles
└── main.js                # Frontend JS (graph logic)
```

---

## 📄 License

This project is licensed under the **MIT License**.
Feel free to use, modify, and contribute!


