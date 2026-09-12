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
└──────────────────────────────┘
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

### Testing & DevOps

| Technology | Purpose |
|-----------|---------|
| [pytest](https://pytest.org) | Backend unit testing |
| Git | Version control |
| npm | Frontend package management |
| pip + venv | Backend dependency management |

---

## 📁 Project Structure

```
PhishShield/
│
├── index.html                     # Vite entry point
├── package.json                   # Frontend dependencies
├── vite.config.js                 # Vite + React + Tailwind config
├── .env.example                   # Frontend environment template
│
├── src/                           # ── Frontend (React) ──────────────
│   ├── main.jsx                   # App bootstrap
│   ├── App.jsx                    # Root component + routing
│   ├── config.js                  # Runtime config (demo mode, thresholds)
│   ├── index.css                  # Global styles + Tailwind imports
│   │
│   ├── pages/
│   │   ├── Home.jsx               # Landing page
│   │   ├── Analyze.jsx            # URL analysis page
│   │   ├── History.jsx            # Scan history viewer
│   │   └── HowItWorks.jsx         # Feature explanation page
│   │
│   ├── components/
│   │   ├── Navbar.jsx             # Top navigation bar
│   │   ├── Footer.jsx             # Footer
│   │   ├── URLAnalyzer.jsx        # URL input form
│   │   ├── AnalysisLoader.jsx     # Loading animation
│   │   └── ResultCard.jsx         # Verdict + risk gauge + features
│   │
│   ├── services/
│   │   └── api.js                 # API client (demo/live toggle)
│   │
│   ├── data/
│   │   └── mockData.js            # Demo mode mock responses
│   │
│   └── hooks/
│       └── useTheme.js            # Dark/light theme hook
│
├── backend/                       # ── Backend (Python) ──────────────
│   ├── requirements.txt           # Python dependencies
│   ├── .env.example               # Backend environment template
│   ├── .gitignore                 # Backend-specific ignores
│   ├── README.md                  # Backend-specific docs
│   │
│   ├── app/
│   │   ├── main.py                # FastAPI entry point + lifespan
│   │   ├── config.py              # Env config, paths, thresholds
│   │   │
│   │   ├── api/
│   │   │   └── routes.py          # POST /api/v1/analyze endpoint
│   │   │
│   │   ├── schemas/
│   │   │   └── analyze.py         # Pydantic request/response models
│   │   │
│   │   ├── services/
│   │   │   ├── url_features.py    # 35-feature extraction engine
│   │   │   ├── predictor.py       # ML prediction service
│   │   │   └── explainer.py       # Explainable AI reasons
│   │   │
│   │   └── utils/
│   │       └── url_utils.py       # URL normalization & validation
│   │
│   ├── ml/
│   │   ├── train.py               # Full training pipeline (CLI)
│   │   ├── preprocess.py          # Data loading, cleaning, feature matrix
│   │   ├── evaluate.py            # Metrics: accuracy, F1, ROC-AUC, etc.
│   │   └── features.py            # Re-exports from url_features.py
│   │
│   ├── models/                    # Trained model artifacts (gitignored)
│   │   ├── model.pkl              # Serialized ML model
│   │   └── metadata.json          # Training metadata & metrics
│   │
│   ├── data/
│   │   └── raw/                   # Training datasets (gitignored)
│   │       └── .gitkeep
│   │
│   └── tests/
│       ├── test_features.py       # 14 tests — feature extraction
│       ├── test_api.py            # 13 tests — URL utilities
│       └── test_predictor.py      # 3 tests — explainer service
```

---

## 🚀 Getting Started

### Prerequisites

- **Node.js** ≥ 18 and **npm**
- **Python** ≥ 3.10 (tested on 3.14.7)
- **Git**

### 1. Frontend Setup

```bash
# Clone the repository
git clone https://github.com/your-username/phishshield-ai.git
cd phishshield-ai

# Install dependencies
npm install

# Start the dev server (demo mode by default)
npm run dev
```

The frontend will be available at **http://localhost:5173** in demo mode with mock data.

### 2. Backend Setup

```bash
# Navigate to backend
cd backend

# Create a virtual environment
python -m venv .venv

# Activate it
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install pytest   # for testing

# Copy environment config
cp .env.example .env

# Start the API server
uvicorn app.main:app --reload --port 8000
```

Verify:
- Health check: http://localhost:8000/health
- Swagger docs: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### 3. ML Model Training

Place a CSV dataset with `url` and `label` columns (0 = legitimate, 1 = phishing) in `backend/data/raw/`:

```bash
cd backend

# Auto-discover CSV in data/raw/
python -m ml.train

# Or specify a path explicitly
python -m ml.train --dataset path/to/dataset.csv
```

The training pipeline will:
1. Load and auto-detect column/label formats
2. Clean duplicates and null values
3. Extract 35 features from every URL
4. Split data using domain-aware leakage prevention
5. Train a Logistic Regression baseline
6. Train a Random Forest primary model (200 estimators)
7. Compare models by validation F1-score
8. Evaluate the winner on a held-out test set
9. Save `model.pkl` and `metadata.json` to `backend/models/`

### 4. Connect Frontend to Backend

Create or update the root `.env` file:

```env
VITE_DEMO_MODE=false
VITE_API_BASE_URL=http://localhost:8000
```

Restart the frontend (`npm run dev`) — it will now send live requests to the backend API.

---

## 📡 API Reference

### `GET /health`

Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "service": "phishshield-ai",
  "model_loaded": true
}
```

### `POST /api/v1/analyze`

Analyze a URL for phishing risk.

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "verdict": "safe",
  "risk_score": 12,
  "confidence": 0.88,
  "top_reasons": [
    "Uses HTTPS encryption.",
    "No deceptive login keywords detected.",
    "URL structure is concise and consistent."
  ],
  "features": {
    "url_length": 23,
    "hostname_length": 11,
    "path_length": 0,
    "num_dots": 1,
    "num_hyphens": 0,
    "num_subdomains": 0,
    "suspicious_keyword_count": 0,
    "digit_ratio": 0.0,
    "special_character_count": 0,
    "entropy": 3.42,
    "has_https": true,
    "has_ip": false,
    "has_port": false
  },
  "processing_time_ms": 4,
  "model_version": "rf-v1",
  "timestamp": "2026-09-12T10:30:00.000Z"
}
```

**Error Responses:**

| Status | Condition |
|--------|-----------|
| `400` | Invalid URL (empty, bad scheme, no hostname) |
| `503` | ML model not loaded (not yet trained) |
| `500` | Prediction failure |

### Interactive Docs

| Docs | URL |
|------|-----|
| Swagger UI | http://localhost:8000/docs |
| ReDoc | http://localhost:8000/redoc |

---

## 🧠 ML Pipeline

```
 CSV Dataset
     │
     ▼
 Load & Clean ──────── Flexible column/label detection
     │                  Supports: 0/1, legitimate/phishing,
     │                  good/bad, benign/phishing
     ▼
 Domain-Aware Split ── Prevents data leakage by splitting
     │                  on registered domain, not individual URLs
     │                  (fallback: stratified split)
     ▼
 Feature Extraction ── 35 features per URL
     │                  (see Feature Engineering section)
     ▼
 Train Baseline ────── Logistic Regression
     │                  (class_weight="balanced", max_iter=1000)
     ▼
 Train Primary ─────── Random Forest Classifier
     │                  (n_estimators=200, max_depth=20,
     │                   class_weight="balanced")
     ▼
 Compare ───────────── Select best by validation F1-score
     │
     ▼
 Evaluate ──────────── Final test set: Accuracy, Precision,
     │                  Recall, F1, ROC-AUC, Confusion Matrix
     ▼
 Save ──────────────── model.pkl + metadata.json
```

### Verdict Thresholds

| Risk Score | Verdict | Label |
|-----------|---------|-------|
| 0 – 39 | `safe` | Low risk |
| 40 – 69 | `suspicious` | Moderate risk |
| 70 – 100 | `phishing` | High risk |

---

## 🔬 Feature Engineering

The engine extracts **35 canonical features** from each URL string — organized into 6 categories:

### Basic Structure (16 features)

| Feature | Description |
|---------|-------------|
| `url_length` | Total character count of the URL |
| `hostname_length` | Length of the hostname |
| `path_length` | Length of the URL path |
| `query_length` | Length of the query string |
| `fragment_length` | Length of the URL fragment |
| `num_dots` | Count of `.` characters |
| `num_hyphens` | Count of `-` characters |
| `num_underscores` | Count of `_` characters |
| `num_slashes` | Count of `/` characters |
| `num_question_marks` | Count of `?` characters |
| `num_equals` | Count of `=` characters |
| `num_ampersands` | Count of `&` characters |
| `num_percent_chars` | Count of `%` (encoding) characters |
| `num_digits` | Total digit count in URL |
| `num_letters` | Total letter count in URL |
| `special_character_count` | Non-alphanumeric, non-structural characters |

### Hostname Analysis (5 features)

| Feature | Description |
|---------|-------------|
| `num_subdomains` | Subdomain depth (e.g. `a.b.example.com` → 2) |
| `has_ip` | Whether hostname is an IPv4 address |
| `hostname_digit_count` | Digits in the hostname |
| `hostname_hyphen_count` | Hyphens in the hostname |
| `hostname_dot_count` | Dots in the hostname |

### Protocol & Security (4 features)

| Feature | Description |
|---------|-------------|
| `has_https` | Uses HTTPS scheme |
| `has_http` | Uses HTTP scheme |
| `has_port` | Explicit port in URL |
| `non_standard_port` | Port is not 80 or 443 |

### Lexical Signals (1 feature)

| Feature | Description |
|---------|-------------|
| `suspicious_keyword_count` | Count of 28 phishing keywords (login, verify, account, etc.) |

### Entropy & Complexity (5 features)

| Feature | Description |
|---------|-------------|
| `entropy` | Shannon entropy of the full URL |
| `hostname_entropy` | Shannon entropy of the hostname |
| `digit_ratio` | Proportion of digits in the URL |
| `special_char_ratio` | Proportion of special characters |
| `character_diversity` | Unique characters / total length |

### Domain & Path Signals (4 features)

| Feature | Description |
|---------|-------------|
| `path_has_login_keyword` | Path contains login/verify/authenticate terms |
| `query_has_sensitive_keyword` | Query string contains password/token/session terms |
| `hostname_has_suspicious_keyword` | Hostname contains phishing keywords |
| `long_token_count` | Tokens longer than 20 characters (obfuscation signal) |

---

## 🔐 Security Design

PhishShield AI is built with security as a **first-class constraint**:

| Principle | Implementation |
|-----------|----------------|
| **No URL fetching** | The system never opens, crawls, downloads, or visits submitted URLs |
| **Lexical analysis only** | All 35 features are extracted from the URL string — no network requests |
| **CORS restrictions** | API only accepts requests from configured frontend origins (no `*`) |
| **Input validation** | Pydantic enforces URL length limits (max 4096 chars), scheme allowlist |
| **No secrets in code** | All configuration via `.env` files (gitignored) |
| **Graceful degradation** | API returns 503 if model isn't trained — no crashes |

### What the system does NOT do:
- ❌ Open submitted URLs in a browser
- ❌ Crawl or download webpage content
- ❌ Use `requests.get()` on submitted URLs
- ❌ Execute JavaScript from submitted URLs
- ❌ Load submitted URLs in iframes
- ❌ Visit submitted domains automatically

---

## 🧪 Testing

### Backend Tests

```bash
cd backend

# Run all tests
python -m pytest tests/ -v

# Run specific test files
python -m pytest tests/test_features.py -v    # 14 feature extraction tests
python -m pytest tests/test_api.py -v         # 13 URL utility tests
python -m pytest tests/test_predictor.py -v   # 3 explainer tests
```

### Test Coverage

| Test Suite | Tests | Coverage |
|-----------|-------|----------|
| `test_features.py` | 14 | Feature extraction, entropy, vector ordering, keyword detection |
| `test_api.py` | 13 | URL normalization, validation, scheme checks, IPv4 detection |
| `test_predictor.py` | 3 | Explainer reasons for safe URLs, phishing URLs, max-5 cap |
| **Total** | **30** | |

### Frontend

```bash
# Build check (verifies no compilation errors)
npm run build
```

---

## ⚙️ Environment Variables

### Frontend (`.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_DEMO_MODE` | `true` | Use mock data (`true`) or live backend (`false`) |
| `VITE_API_BASE_URL` | `http://localhost:8000` | Backend API base URL |

### Backend (`backend/.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `development` | Application environment |
| `HOST` | `127.0.0.1` | Server host |
| `PORT` | `8000` | Server port |
| `MODEL_PATH` | `models/model.pkl` | Path to trained model |
| `METADATA_PATH` | `models/metadata.json` | Path to training metadata |
| `FRONTEND_ORIGINS` | `http://localhost:5173` | Comma-separated CORS origins |

---

## 🗺️ Roadmap

- [x] React frontend with demo mode
- [x] FastAPI backend with REST API
- [x] 35-feature URL extraction engine
- [x] ML training pipeline (LR + Random Forest)
- [x] Explainable AI reasons
- [x] Pydantic request/response validation
- [x] Domain-aware data splitting
- [x] Unit tests (30 tests)
- [x] Backend dependencies installed
- [ ] Train model on real phishing dataset
- [ ] End-to-end integration testing
- [ ] Frontend ↔ Backend live connection
- [ ] Performance benchmarking
- [ ] Security audit
- [ ] Production deployment guide
- [ ] CI/CD pipeline
- [ ] Docker containerization
- [ ] Browser extension

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Built with ❤️ for safer browsing<br/>
  <strong>PhishShield AI</strong> — Detect phishing before you click.
</p>
