"""Web app and API. Start with:  python run_server.py   then open http://127.0.0.1:8000"""

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from phishguard.config import BASE_DIR, MAX_UPLOAD_BYTES
from phishguard.pipeline import PhishGuardPipeline

app = FastAPI(title="PhishGuard AI")
pipeline = PhishGuardPipeline()


class TextRequest(BaseModel):
    subject: str = ""
    sender: str = ""
    body: str = ""
    headers: str = ""


@app.get("/")
def index():
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "content_backend": pipeline.content.backend}


@app.post("/api/analyze/eml")
async def analyze_eml(file: UploadFile = File(...)):
    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File is larger than 25 MB.")
    if not raw.strip():
        raise HTTPException(status_code=400, detail="The file is empty.")
    return pipeline.analyze_raw(raw)


@app.post("/api/analyze/text")
def analyze_text(request: TextRequest):
    if not (request.body.strip() or request.headers.strip()):
        raise HTTPException(status_code=400, detail="Paste the email text first.")
    return pipeline.analyze_fields(request.subject, request.sender, request.body, request.headers)
