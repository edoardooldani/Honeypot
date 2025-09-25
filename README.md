# 🍯 Honeypot

A **distributed honeypot system** with real-time traffic analysis and anomaly detection powered by AI.

---

## 📖 Overview

Honeypot is a project combining a **Rust server** and a **Rust client** to deploy virtual honeypots and analyze malicious traffic in real time.  
Its goal is to capture intrusion attempts, study attacker behavior, and identify anomalous patterns through machine learning models.

---

## 🧱 Architecture

### 🖥️ Server (Rust)

- Exposes **REST APIs** for:
  - User login and authentication
  - (Planned) device registration and configuration
- Provides a **secure WebSocket endpoint** (`/ws`) for client communication with TLS
- Handles orchestration and centralized event logging

### 📡 Client (Python)

- Connects to the server via **TLS WebSocket**
- Deploys **virtual honeypots** that simulate services/protocols and respond to attacker scans
- Every captured packet is:
  - Grouped into a **flow** (source host, destination host, protocol)
  - Processed by an **autoencoder** for anomaly detection
  - Classified by a **classifier** to label the attack type

### 🤖 AI & ML (Python)

- Development and training of **autoencoder** and **classifier** models
- Hyperparameter tuning and performance validation


## ⚙️ Requirements 
- server/certs folder with CA.pem and server-cert.pem issued by the same CA of the client
- client/certs folder with CA.pem and client-cert.pem issued by the same CA of the server
- InfluxDB Buckets for network logs
