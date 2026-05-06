# Secure AI Proxy — Privacy-Preserving AI Gateway

> **"Like credit card tokenization — but for any data you send to an LLM."**
>
> A proxy that sits between your business and any external AI model.
> Real PII never leaves your perimeter. The LLM sees only random tokens.

🔗 **Live demo:** `http://51.105.241.83:8000/docs`

---

## The Problem

When a business uses an external LLM (OpenAI, Groq, Claude), sensitive data —
customer names, IDs, salaries, emails — is sent in plain text to a third-party server.
This creates legal exposure (GDPR, HIPAA) and security risk.

## The Solution

```
User prompt (with PII)
        │
        ▼
┌─────────────────────────────┐
│     Secure AI Proxy         │  ← your data never leaves here
│                             │
│  1. Detect PII              │  "John Smith, ID 123456789"
│  2. Replace with tokens     │  "TKN_NAME_A3F1, ID TKN_ID_9B2C"
│  3. Store mapping (encrypted)│
└────────────┬────────────────┘
             │  tokens only — zero real data
             ▼
    LLM (Groq / OpenAI)          ← sees: "TKN_NAME_A3F1 needs help with..."
             │
             ▼
┌─────────────────────────────┐
│     Detokenization          │  TKN_NAME_A3F1 → "John Smith"
└─────────────────────────────┘
             │
             ▼
   Clean response → user        ← "John Smith, here is your answer..."
```

---

## Architecture

| Component | Technology | Role |
|---|---|---|
| **Orchestrator** | FastAPI + Python 3.12 | Request routing, flow control |
| **MaskingEngine** | Regex (6 entity types) | PII detection and tokenization |
| **Token Store** | In-memory (Redis-ready) | Token ↔ original mapping |
| **LLM Backend** | Groq (llama-3.3-70b) | AI processing — zero PII |
| **Infrastructure** | Azure VM + Docker | Cloud deployment |

### PII Entity Types Detected

- `full_name_hebrew` — שמות עבריים
- `full_name_latin` — Latin names (First Last)
- `israeli_id` — 9-digit Teudat Zehut
- `email` — email addresses
- `salary` — ₪ / NIS / $ amounts
- `phone_il` — Israeli phone numbers
- `credit_card` — 13-19 digit card numbers

---

## Quick Start

### Prerequisites
- Docker
- A Groq API key (free at [console.groq.com](https://console.groq.com))

### Run locally

```bash
git clone https://github.com/YOUR_USERNAME/secure-ai-proxy
cd secure-ai-proxy

# Configure environment
cp .env.example .env
# Edit .env: set GROQ_API_KEY, MODEL_NAME=llama-3.3-70b-versatile

# Run with Docker
docker build -t secure-ai-proxy .
docker run -d \
  --name firewall-active \
  -p 8000:8000 \
  -v $(pwd):/app_context \
  -w /app_context \
  -e DEBUG=true \
  --env-file .env \
  secure-ai-proxy \
  uvicorn app.main:app --host 0.0.0.0 --port 8000

# Open Swagger UI
open http://localhost:8000/docs
```

---

## Demo: What the LLM Actually Sees

Send this to `/chat`:
```json
{
  "session_id": "demo-001",
  "prompt": "My name is John Smith, ID 123456789, email john@gmail.com, salary $8,000. Write me a professional bio.",
  "system_prompt": "You are a helpful assistant."
}
```

**What leaves your server (what the LLM sees):**
```
My name is TKN_NAME_A3F1, ID TKN_ID_9B2C, 
email TKN_EMAIL_4D7E, salary TKN_SALARY_1F8A. 
Write me a professional bio.
```

**What comes back to the user:**
```
John Smith is a dedicated professional with ID 123456789...
reachable at john@gmail.com...
```

Check the server logs to see the full audit trail:
```bash
docker logs firewall-active
```

---

## API Endpoints

### `POST /chat`
Full secure proxy flow — mask, send to LLM, detokenize.

```bash
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "uuid-here",
    "prompt": "your prompt with PII",
    "system_prompt": "optional system context"
  }'
```

### `POST /mask`
Test the masking engine without calling the LLM.

```bash
curl -X POST http://localhost:8000/mask \
  -H "Content-Type: application/json" \
  -d '{"text": "שמי ישראל ישראלי, תז 123456789"}'
```

### `GET /health`
Liveness probe for load balancers.

---

## Roadmap

- [x] PII detection — 6 entity types
- [x] Token substitution and detokenization
- [x] Groq / OpenAI-compatible LLM integration
- [x] Docker deployment on Azure
- [x] Audit logging (zero-trust evidence)
- [ ] Redis persistent token store
- [ ] API key authentication for business clients
- [ ] Format-Preserving Tokenization (FPT)
- [ ] Dashboard with audit analytics
- [ ] Microsoft Presidio NER as second detection layer
- [ ] Multi-tenant policy engine

---

## Security Design

**Zero-Trust principle:** The LLM is treated as an untrusted third party.
It receives only opaque tokens — even a complete breach of the LLM provider
exposes nothing about the original data.

**Token design:** Tokens are session-scoped and randomly generated (`os.urandom`).
The same value in the same session always maps to the same token (deduplication),
but different sessions produce different tokens.

**No raw PII in logs:** The audit log records token names and entity types,
never the original values.

---

## Why This Matters

| Scenario | Without proxy | With proxy |
|---|---|---|
| OpenAI breach | Customer PII exposed | Only opaque tokens exposed |
| GDPR audit | "We sent names to OpenAI" | "We sent TKN_NAME_xxxx to OpenAI" |
| Employee misuse | Logs show full prompts | Logs show only tokens |
| Multi-cloud AI | Lock-in to one provider | Any OpenAI-compatible API |

---

## Tech Stack

```
Python 3.12 · FastAPI · Uvicorn · httpx · Pydantic v2
Docker · Azure VM · Groq API (llama-3.3-70b-versatile)
```

---

## Author

Built as a cybersecurity MVP demonstrating privacy-preserving AI architecture.
Inspired by payment tokenization standards (PCI-DSS) applied to the LLM space.
