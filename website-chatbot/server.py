"""Skerry travel site: serves the page and passes its chat to RagMonitor with the site's API token.

Run from this folder:  uvicorn server:app --port 4000

The token lives in website-chatbot/.env on this server and is sent as a Bearer header to
RagMonitor's POST /v1/chat. The browser only ever talks to this server, so it never sees the token.
"""
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

HERE = Path(__file__).resolve().parent


def load_env(path):
    """Minimal .env reader: KEY=VALUE lines, # comments. Real environment variables win."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"'))


load_env(HERE / ".env")
RAGMON_URL = os.environ.get("RAGMON_URL", "http://localhost:8000").rstrip("/")
RAGMON_TOKEN = os.environ.get("RAGMON_TOKEN", "")

app = FastAPI(title="Skerry")


class AttachmentIn(BaseModel):
    name: str
    content: str


class ChatIn(BaseModel):
    question: str
    session: str = "web"
    attachment: AttachmentIn | None = None


@app.post("/api/chat")
def chat(body: ChatIn):
    if not RAGMON_TOKEN:
        raise HTTPException(503, "The assistant is not connected yet. Set RAGMON_TOKEN in website-chatbot/.env.")
    question = body.question.strip()[:1500]
    if not question:
        raise HTTPException(400, "Ask a question first.")
    payload = {"question": question, "session": body.session[:64]}
    if body.attachment:
        if len(body.attachment.content) > 20000:
            raise HTTPException(413, "That file is too long. Attach a text file under 20,000 characters.")
        payload["attachment"] = {"name": body.attachment.name[:120], "content": body.attachment.content}
    req = urllib.request.Request(
        f"{RAGMON_URL}/v1/chat",
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json", "authorization": f"Bearer {RAGMON_TOKEN}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise HTTPException(503, "The assistant's API token was rejected. Create a new one in RagMonitor.")
        raise HTTPException(502, "The assistant could not answer that. Try again in a moment.")
    except OSError:
        raise HTTPException(502, "The assistant is offline right now. Email support@skerry.ie instead.")
    return {"answer": data.get("answer", "")}


# Routes above take precedence; everything else is the static site.
app.mount("/", StaticFiles(directory=HERE / "site", html=True), name="site")
