# 🎯 NetGuardAI - Interview Cheat Sheet

> **Quick reference for interviews. Keep this short and simple!**

---

## 1. Project Summary (30 seconds pitch)

> "I built a real-time network traffic analyzer that captures packets, detects security threats using pattern matching AND machine learning, and displays everything in a live web dashboard. It's containerized with Docker for easy deployment."

---

## 2. Core Technologies

| Tech | What I Used It For |
|------|-------------------|
| **Python** | Main language |
| **Scapy** | Capture network packets |
| **SQLite** | Store packet data |
| **Pandas** | Clean and analyze data |
| **Streamlit** | Web dashboard |
| **Scikit-learn** | ML anomaly detection |
| **Docker** | Containerized deployment |

---

## 3. Key Concepts (Simple!)

### What is Packet Sniffing?

Capturing network data as it travels. Like reading postcards passing through a mail room.

### What is Isolation Forest?

ML algorithm that finds "weird" data. It tries to isolate each point - weird points are easy to isolate, normal points are hard.

### What is SQL Injection?

Attacker puts code like `' OR '1'='1` in inputs to trick the database.

### What is Docker?

Packages your app + dependencies in a container that works the same everywhere.

---

## 4. Top 10 Interview Questions

**Q1: Explain your project.**
> "Real-time packet capture → SQLite storage → ML anomaly detection → Web dashboard. All containerized in Docker."

**Q2: Why Scapy?**
> "Python-native, can parse/forge packets, understands 100+ protocols."

**Q3: Why SQLite?**
> "No server needed, single file, perfect for single-machine apps."

**Q4: How does your ML work?**
> "Isolation Forest - unsupervised, doesn't need labeled data, good for rare anomalies."

**Q5: How do you prevent SQL injection?**
> "Parameterized queries with `?` placeholders. Input is treated as data, never code."

**Q6: What's Docker do?**
> "Packages app + dependencies. One command to run anywhere."

**Q7: Hardest bug?**
> "Dashboard freezing - SQLite locking issue. Fixed with timeout and persistent connection."

**Q8: How would you scale this?**
> "PostgreSQL for DB, Kafka for streaming, Kubernetes for containers."

**Q9: What attacks can you detect?**
> "SQL injection, XSS (regex), anomalous packet sizes (ML)."

**Q10: What did you learn?**
> "Full-stack development, production debugging, ML integration, containerization."

---

## 5. Quick Commands

```bash
# Start everything
docker-compose up -d

# View logs
docker logs netguardai

# Stop everything
docker-compose down

# Test ML locally
python test_ml.py

# Test security locally
python test_security.py
```

---

## 6. File Structure

```
NetGuardAI/
├── sniffer.py      # Captures packets
├── dashboard.py    # Web UI
├── security.py     # Pattern detection
├── ml_detector.py  # ML anomaly detection
├── data_loader.py  # Database access
├── Dockerfile      # Container build
└── docker-compose.yml  # Easy deployment
```

---

**Good luck with your interviews! 🚀**
