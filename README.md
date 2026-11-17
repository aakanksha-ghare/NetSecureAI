# NetSecureAI

NetSecureAI is an AI-driven multi-vendor network security compliance auditor.
The current application foundation provides a health endpoint; it does not yet
perform compliance audits or claim support for any vendors.

## Run locally

From the project root, activate the project environment and start the Flask
development server:

```powershell
.\.venv314\Scripts\Activate.ps1
python run.py
```

The health endpoint is available at `http://127.0.0.1:5000/health`.

## Run tests

From the project root, run:

```powershell
python -m pytest -q
```