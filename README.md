# DataResQ — Render Web Edition

This is the browser-compatible conversion of the supplied **DataResQ** PySide6 desktop project.

### Reused from the original project
- `secure_file.py` — AES-256-GCM encryption/decryption
- `recovery/` — signature detection and file carving
- `sanitization/sanitization_engine.py` — controlled file overwrite/delete logic
- `analysis/forensic_analyzer.py` — metadata and SHA-256 analysis
- `forensics.py` — case/event logging
- `reporting.py` — HTML forensic report generation

### Replaced for the browser
- The PySide6 desktop UI has been replaced by a Flask web interface in `app.py` + `templates/` + `static/`.
- Windows drive-level sanitization is not exposed because a cloud web service cannot safely operate on a user's local physical drive.

## Render settings

| Setting | Value |
|---|---|
| Service | Web Service |
| Runtime | Python 3 |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `gunicorn app:app` |
| Root Directory | leave blank when these files are at repository root |

Render's current Flask deployment guide uses the same build/start commands. See the official Render documentation.

## Local run

```bash
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000`.

## Important deployment note

The web edition is intended for demonstration, authorized testing and project presentation. Free cloud instances use temporary server storage, so do not use the deployment as a permanent evidence repository. Secure erasure on a cloud filesystem cannot be represented as a guarantee about physical storage media.
