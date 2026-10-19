<div align="center">

# 🛠️ SRE-Agent

### Autonomous Self-Healing DevOps System

**An AI agent that detects, diagnoses, remediates, and verifies production incidents — with zero human intervention.**

[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20-339933?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org/)
[![LangChain](https://img.shields.io/badge/LangChain-Agentic_AI-1C3C3C?style=flat-square&logo=langchain&logoColor=white)](https://www.langchain.com/)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-Vector_Store-FF6F61?style=flat-square)](https://www.trychroma.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

[Overview](#-overview) •
[How It Works](#-how-it-works) •
[Quick Start](#-quick-start) •
[Architecture](#-architecture) •
[API Reference](#-api-reference) •
[Demo](#-demo)

</div>

---

## 📌 Overview

Most monitoring stacks stop at **detection**. Prometheus, Datadog, and PagerDuty are excellent at telling a human *"something is wrong"* — but the actual diagnosis and fix almost always still requires a person to wake up, investigate, and act.

**SRE-Agent closes that loop.**

It's a fully containerized system that continuously watches a live application, and when a real incident occurs — a memory leak, a database connection failure, a CPU spike — it:

1. **Detects** the failure in real time
2. **Diagnoses** it using a Retrieval-Augmented Generation (RAG) pipeline over a curated runbook knowledge base
3. **Remediates** it by executing real, safety-constrained Docker commands
4. **Verifies** the fix actually worked before declaring the incident resolved

All of this happens autonomously, in seconds, with a full audit trail — no human ever touches it.

> This isn't a chatbot wrapper around a monitoring dashboard. It's a working, tool-using AI agent operating real infrastructure under explicit safety constraints.

---

## 🧠 How It Works

```
   ┌──────────────┐        polls /health every 10s        ┌──────────────────┐
   │              │────────────────────────────────────▶  │                  │
   │  Target App  │                                        │  Monitor Service │
   │  (Node.js)   │◀────────────────────────────────────── │   (FastAPI)      │
   │              │           detects failure               │                  │
   └──────┬───────┘                                        └────────┬─────────┘
          │                                                          │
          │  docker restart / logs / inspect                         │ sends captured
          │  (allow-listed, via Docker socket)                       │ logs + trigger
          │                                                          ▼
          │                                                ┌──────────────────┐
          └────────────────────────────────────────────────│    Agent Brain    │
                                                             │ LangChain + RAG  │
                                                             │ + ChromaDB + LLM │
                                                             └──────────────────┘
```

1. The **monitor** polls the target app's `/health` endpoint every 10 seconds.
2. On failure (timeout, HTTP 503, or connection refused), it captures recent container logs.
3. It sends the incident context to the **agent brain**.
4. The agent performs a **vector similarity search** over a runbook knowledge base (ChromaDB) to find the best-matching documented fix.
5. It reasons over the runbook using an LLM (Gemini / OpenAI / Anthropic — configurable) and executes the remediation via a **strictly allow-listed** Docker CLI interface.
6. The monitor **independently re-verifies** health before marking the incident resolved.
7. Every step is logged and queryable via a REST API.

---

## ✨ Key Features

- 🔁 **Fully autonomous incident lifecycle** — detect → diagnose → remediate → verify, no human in the loop
- 📚 **RAG-grounded decisions** — the agent doesn't freely hallucinate fixes; it matches against real, reviewed runbooks
- 🔒 **Constrained tool use** — the agent can only call a fixed, allow-listed set of Docker commands against an explicit container allow-list. No shell access, ever.
- ✅ **Closed-loop verification** — the system checks its own work; a command being issued is never treated as proof of success
- 🔌 **Multi-LLM support** — swap between Gemini, OpenAI, and Anthropic via a single environment variable
- 🧪 **Built-in chaos engineering** — trigger memory leaks, DB failures, and CPU spikes on demand to test the system honestly
- 📊 **Full incident audit trail** — every detection, log snippet, agent decision, and outcome is recorded and queryable

---

## 🏗️ Architecture

| Service | Tech | Responsibility |
|---|---|---|
| `target-app` | Node.js + Express | Simulated production API with `/health`, `/data`, and chaos-injection endpoints |
| `monitor` | Python + FastAPI | Polls health, classifies incidents, captures logs, triggers remediation, verifies recovery |
| `agent-brain` | Python + FastAPI + LangChain + ChromaDB | RAG-based runbook matching, LLM reasoning, allow-listed Docker remediation |

All three services run as isolated Docker containers on a shared bridge network, orchestrated with a single `docker-compose.yml`.

---

## 🚀 Quick Start

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or native Docker on Linux)
- An API key from **one** of: [Google AI Studio](https://aistudio.google.com/) (Gemini), [OpenAI](https://platform.openai.com/), or [Anthropic](https://console.anthropic.com/)

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/Vigneshyadala/sre-agent.git
cd sre-agent

# 2. Configure your LLM provider and API key
cp agent-system/.env.example agent-system/.env
# Edit .env: set LLM_PROVIDER and the matching API key

# 3. Build and start all services
docker compose up -d

# 4. Confirm everything is healthy
docker compose ps
```

### Run a Live Demo Incident

```bash
# Check baseline health
curl http://localhost:3500/health

# Trigger a simulated memory leak
curl http://localhost:3500/chaos/leak

# Watch the full detect → heal → verify cycle in real time
docker compose logs -f monitor

# Review the full incident history
curl http://localhost:8000/incidents
```

Other chaos endpoints: `POST /chaos/db` (database failure), `POST /chaos/cpu` (CPU spike), `POST /chaos/reset` (manual recovery).

---

## 📡 API Reference

### Target App — `:3500`

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Liveness probe — returns `rssMB`, `heapUsedMB`, `heapTotalMB`, `externalMB` |
| `/data` | GET | Simulated business endpoint |
| `/chaos/leak` | GET | Triggers a simulated memory leak |
| `/chaos/db` | GET | Triggers a simulated DB connection failure |
| `/chaos/cpu` | GET | Triggers a synchronous CPU spike |
| `/chaos/reset` | POST | Manually resets all chaos state |

### Monitor — `:8000`

| Endpoint | Method | Description |
|---|---|---|
| `/incidents` | GET | Full incident history — detection trigger, captured logs, agent reasoning, resolution status |

### Agent Brain — `:8001`

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Agent-brain liveness check |
| `/heal` | POST | Invoked by the monitor with incident context; returns the agent's diagnosis and action taken |

---

## 🎥 Demo

> *Add your screen recording or GIF here showing the full detect → diagnose → remediate → verify cycle.*

```
[monitor] Incident detected: http_503. Capturing logs...
[monitor] Invoking SRE-Agent brain...
[monitor] Agent report received:
The "JavaScript Heap Out of Memory (Memory Leak)" runbook was matched.
I restarted the sre-target-app container to clear the leaked heap allocations.
The health check now reports a 200 OK status, indicating the service has recovered.
[monitor] Target recovered. Resolving open incident.
```

---

## 🛡️ Safety Design

This project treats agentic AI autonomy as something to be **earned through constraints**, not assumed:

- The agent can **only** invoke a fixed set of Docker verbs: `restart`, `logs`, `ps`, `stats`, `start`, `stop`, `inspect`
- Target containers are restricted to an **explicit allow-list** — the agent cannot act on containers it wasn't told about
- No shell execution, no arbitrary command construction
- Every remediation is **independently re-verified** before being marked resolved
- Failed remediation attempts are retried once, then escalated rather than looped indefinitely

---

## 🧭 Roadmap

- [ ] Kubernetes-native remediation (replace Docker socket calls with `kubectl` actions)
- [ ] Multi-service monitoring (watch several targets concurrently)
- [ ] Human-in-the-loop approval mode for high-severity incidents
- [ ] Slack/Teams notifications for incident summaries
- [ ] Web dashboard for MTTR trends and agent accuracy
- [ ] Multi-LLM benchmarking harness

---

## 🧰 Tech Stack

`Node.js` `Express` `Python` `FastAPI` `Uvicorn` `LangChain` `ChromaDB` `ONNX (MiniLM-L6-v2)` `Docker` `Docker Compose` `Google Gemini` `OpenAI` `Anthropic`

---

## 👤 Author

**Vignesh Yadala**
Software Engineer / AI Engineer

- Portfolio: [vigneshyadala.github.io/portfolio](https://vigneshyadala.github.io/portfolio/)
- GitHub: [@Vigneshyadala](https://github.com/Vigneshyadala)

This project was independently designed and built end-to-end — architecture, all three services, the RAG-based agent reasoning layer, and the chaos-engineering test harness used to validate it.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**If this project is useful or interesting to you, consider giving it a ⭐**

</div>
