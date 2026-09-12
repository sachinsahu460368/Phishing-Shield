<p align="center">
  <img src="https://img.shields.io/badge/PhishShield-AI-0ea5e9?style=for-the-badge&logo=shield&logoColor=white" alt="PhishShield AI" />
  <img src="https://img.shields.io/badge/React-19.3-61dafb?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/FastAPI-0.141-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/scikit--learn-1.9-f7931e?style=for-the-badge&logo=scikit-learn&logoColor=white" alt="scikit-learn" />
  <img src="https://img.shields.io/badge/Python-3.14-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License" />
</p>

<h1 align="center">🛡️ PhishShield AI</h1>

<p align="center">
  <strong>Real-time phishing URL detection powered by machine learning and 35 URL-based lexical/structural features.</strong>
</p>

<p align="center">
  Paste any URL → get an instant risk verdict with explainable reasons — <em>without ever opening the link.</em>
</p>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Frontend Setup](#1-frontend-setup)
  - [Backend Setup](#2-backend-setup)
  - [ML Model Training](#3-ml-model-training)
  - [Connect Frontend to Backend](#4-connect-frontend-to-backend)
- [Vercel Deployment](#-vercel-deployment)
- [API Reference](#-api-reference)
- [ML Pipeline](#-ml-pipeline)
- [Feature Engineering](#-feature-engineering)
- [Security Design](#-security-design)
- [Testing](#-testing)
- [Environment Variables](#-environment-variables)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 Overview

**PhishShield AI** is a full-stack web application that detects phishing URLs in real-time using machine learning. Users paste a suspicious URL into the analyzer, and the system returns:

- A **risk verdict** — `safe`, `suspicious`, or `phishing`
- A **risk score** from 0 to 100
- A **confidence level** indicating model certainty
- Up to **5 explainable reasons** describing why the URL is flagged
- A **feature breakdown** showing extracted URL characteristics

### 🔒 Core Safety Principle

> The system **never opens, crawls, or fetches** the submitted URL. All analysis is performed through static lexical and structural feature extraction on the URL string itself — making it safe to analyze even known-malicious links.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔎 **Real-time Analysis** | Sub-second URL risk assessment via REST API |
| 🧠 **35-Feature ML Engine** | Extracts lexical, structural, entropy, and semantic features from URLs |
| 🌲 **Random Forest Classifier** | Primary model with Logistic Regression baseline comparison |
| 💡 **Explainable AI** | Human-readable reasons for every verdict — not a black box |
| 🎨 **Modern React UI** | Dark/light theme, animated risk gauge, analysis history |
| 🛡️ **Safe by Design** | Never visits, crawls, or loads the analyzed URL |
| 📊 **Feature Visualization** | Interactive feature grid displayed in the analysis results |
| 🕑 **Analysis History** | Locally stored history of past scans with localStorage |
| 🔁 **Demo Mode** | Fully functional frontend with mock data — no backend required |
| 🌐 **CORS-Secured API** | Origin-restricted API access — no wildcard origins |

---

## 🏗️ Architecture

```
┌─────────────────────────────┐
│      React Frontend         │
│      (Vite :5173)           │
│                             │
│  URLAnalyzer → api.js       │
│     ↓  POST /api/v1/analyze │
└─────────────┬───────────────┘
              │ Axios
              ▼
┌─────────────────────────────┐
│     FastAPI Backend          │
│     (Uvicorn :8000)          │
│                              │
│  routes.py                   │
│    ↓ normalize → validate    │
│    ↓                         │
│  url_features.py             │
│    ↓ 35 features extracted   │
│    ↓                         │
│  predictor.py                │
│    ↓ model.predict_proba()   │
│    ↓                         │
│  explainer.py                │
│    ↓ human-readable reasons  │
│    ▼                         │
│  AnalyzeResponse (JSON)      │
└──────────────┬──────────────┘
               │
               ▼
┌──────────────────────────────┐
│   ML Model (model.pkl)       │
│   Random Forest / LogReg     │
│   Trained on labeled CSV     │
│   35 canonical features      │
└──────────────────────────────┘
```

**Data flow:** URL string → normalize → validate → extract 35 features → model inference → risk score → verdict → explainable reasons → JSON response

---

## 🛠️ Tech Stack

### Frontend

| Technology | Version | Purpose |
|-----------|---------|---------|
| [React](https://react.dev) | 19.3 | UI framework |
| [Vite](https://vite.dev) | 8.3 | Build tool & dev server |
| [Tailwind CSS](https://tailwindcss.com) | 4.3 | Utility-first styling |
| [React Router](https://reactrouter.com) | 7.18 | Client-side routing |
| [Axios](https://axios-http.com) | 1.20 | HTTP client |
| [Recharts](https://recharts.org) | 3.10 | Data visualization |
| [Lucide React](https://lucide.dev) | 1.44 | Icon library |

### Backend

| Technology | Version | Purpose |
|-----------|---------|---------|
| [Python](https://python.org) | 3.14 | Runtime |
| [FastAPI](https://fastapi.tiangolo.com) | ≥0.115 | API framework |
| [Uvicorn](https://uvicorn.org) | ≥0.30 | ASGI server |
| [Pydantic](https://docs.pydantic.dev) | ≥2.9 | Data validation & schemas |
| [python-dotenv](https://github.com/theskumar/python-dotenv) | ≥1.0 | Environment configuration |

### Machine Learning

| Technology | Version | Purpose |
|-----------|---------|---------|
| [scikit-learn](https://scikit-learn.org) | ≥1.6 | ML models (Random Forest, Logistic Regression) |
| [pandas](https://pandas.pydata.org) | ≥2.2 | Data loading & preprocessing |
| [NumPy](https://numpy.org) | ≥2.0 | Numerical computation |
| [SciPy](https://scipy.org) | (auto) | Scientific computing dependency |
| [joblib](https://joblib.readthedocs.io) | ≥1.4 | Model serialization |

---

## 📁 Project Structure

```
PhishShield/
│
├── api/                           # Vercel Serverless Function entrypoint
│   └── index.py
├── requirements.txt               # Root dependencies for Vercel
├── index.html                     # Vite entry point
├── package.json                   # Frontend dependencies
├── vite.config.js                 # Vite + React + Tailwind config
├── .env                           # Root environment config (frontend)
│
├── src/                           # ── Frontend (React) ──────────────
...
├── backend/                       # ── Backend (Python) ──────────────
...
```

---

## 🚀 Getting Started

### Prerequisites

- **Node.js** ≥ 18 and **npm**
- **Python** ≥ 3.10
- **Git**

### 1. Frontend Setup

```bash
# Clone the repository
git clone https://github.com/your-username/phishshield-ai.git
cd phishshield-ai

# Create root .env for frontend
echo "VITE_DEMO_MODE=true
VITE_API_BASE_URL=http://localhost:8000" > .env

# Install dependencies
npm install

# Start the dev server
npm run dev
```

### 2. Backend Setup

```bash
# Navigate to backend
cd backend

# Create a virtual environment
python -m venv .venv
# Activate venv: .venv\Scripts\activate (Windows) or source .venv/bin/activate (Linux/macOS)

# Install dependencies
pip install -r requirements.txt

# Create backend .env
echo "FRONTEND_ORIGINS=http://localhost:5173" > .env

# Start the API server
uvicorn app.main:app --reload --port 8000
```

### 3. ML Model Training & Connection

Follow the detailed ML model training in `backend/README.md`. Once trained:

1. Update root `.env`:
   ```env
   VITE_DEMO_MODE=false
   VITE_API_BASE_URL=http://localhost:8000
   ```
2. Restart frontend: `npm run dev`.

---

## 🌐 Vercel Deployment

PhishShield AI is ready for Vercel deployment using zero-configuration FastAPI support.

### Deployment Prerequisites
- Ensure `requirements.txt` exists at project root.
- Ensure `api/index.py` exists at project root (bridges Vercel to backend).

### Steps
1. Push all code to a Git repository linked to Vercel.
2. In Vercel Project Settings:
   - **Root Directory**: `./`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
3. Add Environment Variables in Vercel:
   - `VITE_API_BASE_URL`: The URL of your deployed Vercel app (e.g., `https://your-project.vercel.app`)
   - `FRONTEND_ORIGINS`: The URL of your deployed Vercel app.

---

## 📡 API Reference

*(See Backend README for details)*

---

## 🧠 ML Pipeline

*(See Backend README for details)*

---

## 🔐 Security Design

*(See Backend README for details)*

---

## 🧪 Testing

```bash
# Frontend
npm run build

# Backend
cd backend
python -m pytest tests/
```

---

## 🗺️ Roadmap

- [x] React frontend with demo mode
- [x] FastAPI backend with REST API
- [x] 35-feature URL extraction engine
- [x] ML training pipeline
- [x] Explainable AI reasons
- [x] Unit tests
- [x] Production deployment guide (Vercel)
- [x] Frontend ↔ Backend live connection

---

## 📄 License
MIT License.
