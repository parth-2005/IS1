# IS1 messaging demo

This small project demonstrates an educational hybrid encryption handshake (RSA implemented by math for teaching) and AES-based messaging.

Structure
- `infoSec/Crypto.py` — educational math-based RSA and AES(CBC) helpers (do not change for pedagogical purposes).
- `messaging/protocol.py` — refactored networking and handshake (server/client) using the crypto helpers.
- `app.py` — thin CLI wrapper that starts `MessagingService` in server or client mode.

Requirements
- Python 3.8+
- See `requirements.txt` (PyCryptodome is used by the AES code in `infoSec/Crypto.py`).

Quick start (PowerShell)
```powershell
pip install -r requirements.txt
python .\app.py
# choose server or client when prompted
```

Notes
- The RSA implementation in `infoSec/Crypto.py` is intentionally kept as a simple math-based implementation for learning. It is not secure for production.
- The current AES routines use CBC mode (also educational). For real applications prefer authenticated AEAD modes (e.g. AES-GCM) and vetted libraries.

If you'd like, I can:
- Add unit tests and a small automated demo that runs both server and client locally.
- Migrate the educational math RSA to the `cryptography` library for a production-ready variant (keeps the educational code for comparison).
