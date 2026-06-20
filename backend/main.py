
from fastapi import FastAPI, HTTPException, Body, UploadFile, File, Form, Query, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from rbac_auth import require_module
import sarvam_client as ollama
import database
import os
import uuid
import datetime
import re
import asyncio
import json
import io
import zipfile
from pypdf import PdfReader
import numpy as np

app = FastAPI(title="Angela - Agentic AI Platform")

# CORS - Allow all for development simplicity, restrict in prod if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize DB on startup
@app.on_event("startup")
def startup_event():
    database.init_db()
    database.reset_inflight_mobile_sast_scans()
    database.reset_inflight_mobile_dast_scans()
    database.reset_inflight_code_scans()
    database.reset_inflight_easm_scans()
    database.reset_inflight_bas_runs()
    database.reset_inflight_threat_model_sessions()
    # Bootstrap default admin if no RBAC users exist
    import rbac_module
    rbac_module.bootstrap_default_admin()
    os.makedirs(get_upload_dir(), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), "threat_model_uploads"), exist_ok=True)
    os.makedirs(get_mobile_sast_upload_dir(), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), "mobile_dast_uploads"), exist_ok=True)
    retention_days = database.get_setting("retention_days")
    if retention_days:
        try:
            database.purge_retention(int(retention_days))
        except Exception:
            pass

# Models
class Message(BaseModel):
    role: str
    content: str
    images: Optional[List[str]] = None

class ChatRequest(BaseModel):
    session_id: Optional[str] = None
    message: str
    images: Optional[List[str]] = None
    model: str = "qwen3:8b"
    mode: str = "general"
    vendor: Optional[str] = None
    rag_k: Optional[int] = 5

class ChatResponse(BaseModel):
    session_id: str
    message: Message
    citations: Optional[List[Dict[str, Any]]] = None

class SessionResponse(BaseModel):
    id: str
    title: str
    created_at: str

# System Prompt
SYSTEM_PROMPT = {
    "role": "system",
    "content": (
        "You are Angela, an intelligent and efficient Agentic AI assistant developed by the AngelOne Security Team. "
        "Your goal is to assist users with fintech-related inquiries, data analysis, and general tasks, with a strong focus on security and data privacy. "
        "You possess advanced capabilities in security analysis, threat detection, and secure coding practices. "
        "You should be professional, concise, and helpful. "
        "Avoid using emojis. Maintain a clean and elegant tone suitable for a financial environment. "
        "You have access to visual capabilities (Qwen3-VL-8B). "
        "If asked about yourself, explicitly state that you are developed by the AngelOne Security Team and highlight your security-focused capabilities. "
        "--- AWARENESS AND HUMAN LAYER SECURITY --- "
        "1. AI Chatbot for Employee Doubts: If a user asks whether a link, email, or message is suspicious, act as an expert InfoSec coach. Analyze the indicators, point out potential red flags (e.g., mismatched domains, urgency, unknown sender), and explicitly advise them NOT to click or share credentials if it is suspicious. "
        "2. Real-Time Coaching & Warnings: If a user attempts to share or asks about sharing sensitive information (e.g., PII, passwords, strategic documents, or internal API keys) outside of secure channels, immediately WARN THEM. Provide real-time coaching on AngelOne's data classification and secure data handling policies."
    )
}

TPRM_PROMPT = {
    "role": "system",
    "content": (
        "You are Angela in TPRM mode. Focus on third-party risk management for fintech vendors. "
        "Provide structured, evidence-first assessments, highlight control gaps, and map findings to security controls. "
        "Ask concise follow-up questions when information is missing. "
        "Deliver outputs as clear bullet points with risk rating, impacted domains, and required remediation steps. "
        "Avoid speculative claims and stay aligned to internal security standards and privacy requirements."
    )
}

def select_system_prompt(mode: str):
    if mode == "tprm":
        return TPRM_PROMPT
    return SYSTEM_PROMPT

def get_upload_dir():
    return os.path.join(os.path.dirname(__file__), "rag_uploads")

def get_mobile_sast_upload_dir():
    return os.path.join(os.path.dirname(__file__), "mobile_sast_uploads")

def sanitize_filename(filename: str) -> str:
    clean = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    return clean[:200] if clean else "document.pdf"


def _detect_mobile_artifact(filename: str, payload: bytes) -> Dict[str, Any]:
    normalized_name = (filename or "").lower()
    if normalized_name.endswith(".apk"):
        platform = "android"
        artifact_type = "apk"
    elif normalized_name.endswith(".ipa"):
        platform = "ios"
        artifact_type = "ipa"
    else:
        return {"error": "Only APK and IPA files are supported"}
    if not payload or len(payload) < 4:
        return {"error": "Uploaded file is empty or truncated"}
    if payload[:2] != b"PK":
        return {"error": "Uploaded mobile artifact is not a valid ZIP container"}
    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as zf:
            names = zf.namelist()
    except Exception:
        return {"error": "Uploaded mobile artifact is not a readable ZIP archive"}
    if artifact_type == "apk":
        if "AndroidManifest.xml" not in names:
            return {"error": "Invalid APK: AndroidManifest.xml not found"}
    if artifact_type == "ipa":
        has_payload_app = any(name.startswith("Payload/") and ".app/" in name for name in names)
        has_info_plist = any(name.startswith("Payload/") and name.endswith(".app/Info.plist") for name in names)
        if not has_payload_app or not has_info_plist:
            return {"error": "Invalid IPA: expected Payload/*.app/Info.plist not found"}
    return {"platform": platform, "artifact_type": artifact_type}

def normalize_text(text: str) -> str:
    return re.sub(r'\s+', ' ', text or '').strip()

def chunk_page_text(page_text: str, page_number: int, max_chars: int = 1200, overlap: int = 150) -> List[Dict[str, Any]]:
    chunks = []
    if not page_text:
        return chunks
    start = 0
    length = len(page_text)
    while start < length:
        end = min(start + max_chars, length)
        chunk = page_text[start:end].strip()
        if chunk:
            chunks.append({
                "content": chunk,
                "page_start": page_number,
                "page_end": page_number
            })
        if end >= length:
            break
        start = max(end - overlap, 0)
    return chunks

def embed_text(text: str, model: str):
    try:
        response = ollama.embeddings(model=model, prompt=text)
        return response["embedding"]
    except Exception as e:
        fallback = os.getenv("OLLAMA_FALLBACK_EMBED_MODEL", "nomic-embed-text")
        if model != fallback:
            response = ollama.embeddings(model=fallback, prompt=text)
            return response["embedding"]
        raise e

def build_rag_context(query: str, session_id: Optional[str], vendor: Optional[str], top_k: int):
    embedding = embed_text(query, os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text"))
    chunks = database.list_chunks_for_retrieval(session_id=session_id, vendor=vendor)
    if not chunks and vendor and not session_id:
        chunks = database.list_chunks_for_retrieval(session_id=None, vendor=vendor)
    query_terms = [term for term in re.split(r'\W+', query.lower()) if len(term) > 2]
    term_set = set(query_terms)
    hint_email = "email" in term_set or "e-mail" in term_set or "mail" in term_set
    hint_author = "author" in term_set or "authors" in term_set or "corresponding" in term_set
    scored = []
    query_vec = np.array(embedding, dtype=np.float32)
    query_norm = np.linalg.norm(query_vec)
    for chunk in chunks:
        chunk_vec = np.array(chunk.get("embedding") or [], dtype=np.float32)
        if chunk_vec.size == 0:
            continue
        denom = (np.linalg.norm(chunk_vec) * query_norm)
        score = float(np.dot(query_vec, chunk_vec) / denom) if denom else 0.0
        content = (chunk.get("content") or "").lower()
        overlap_score = 0.0
        if term_set:
            overlap_hits = sum(1 for term in term_set if term in content)
            overlap_score = overlap_hits / max(len(term_set), 1)
        if hint_email and "@" in content:
            overlap_score += 0.4
        if hint_author and ("author" in content or "authors" in content or "corresponding" in content):
            overlap_score += 0.2
        combined = (0.7 * score) + (0.3 * overlap_score)
        scored.append((combined, chunk))
    scored.sort(key=lambda x: x[0], reverse=True)
    selected = []
    seen = set()
    base_limit = max(top_k, 1)
    for score, chunk in scored:
        if len(selected) >= base_limit:
            break
        chunk_key = chunk.get("id") or chunk.get("vector_id") or f"{chunk.get('document_id')}:{chunk.get('chunk_index')}"
        if chunk_key in seen:
            continue
        selected.append(chunk)
        seen.add(chunk_key)
    if hint_email:
        added = 0
        for score, chunk in scored:
            if added >= 2:
                break
            content = chunk.get("content") or ""
            if "@" not in content:
                continue
            chunk_key = chunk.get("id") or chunk.get("vector_id") or f"{chunk.get('document_id')}:{chunk.get('chunk_index')}"
            if chunk_key in seen:
                continue
            selected.append(chunk)
            seen.add(chunk_key)
            added += 1
    if hint_author:
        added = 0
        for score, chunk in scored:
            if added >= 2:
                break
            page_start = chunk.get("page_start") or 0
            if page_start > 2:
                continue
            chunk_key = chunk.get("id") or chunk.get("vector_id") or f"{chunk.get('document_id')}:{chunk.get('chunk_index')}"
            if chunk_key in seen:
                continue
            selected.append(chunk)
            seen.add(chunk_key)
            added += 1
    citations = []
    context_lines = []
    for chunk in selected:
        if not chunk.get("content"):
            continue
        context_lines.append(f"[DOC:{chunk.get('document_id')} p.{chunk.get('page_start')}-{chunk.get('page_end')}] {chunk.get('content')}")
        citations.append({
            "document_id": chunk.get("document_id"),
            "filename": chunk.get("filename"),
            "page_start": chunk.get("page_start"),
            "page_end": chunk.get("page_end"),
            "vendor": chunk.get("vendor"),
            "doc_type": chunk.get("doc_type")
        })
    return "\n".join(context_lines), citations

@app.get("/api/health")
def health_check():
    return {"status": "ok", "message": "Angela API is running."}

@app.get("/api/models")
def list_models():
    try:
        models = ollama.list()
        return {"models": models}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/sessions", response_model=List[Dict[str, Any]], dependencies=[Depends(require_module("chat"))])
def get_sessions():
    return database.get_sessions()

@app.post("/api/sessions", dependencies=[Depends(require_module("chat"))])
def create_session(title: str = Body(..., embed=True)):
    session_id = database.create_session(title)
    return {"session_id": session_id, "title": title}

@app.get("/api/sessions/{session_id}", dependencies=[Depends(require_module("chat"))])
def get_session_history(session_id: str):
    session = database.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    messages = database.get_messages(session_id)
    return {"session": session, "messages": messages}

@app.delete("/api/sessions/{session_id}", dependencies=[Depends(require_module("chat"))])
def delete_session(session_id: str):
    database.delete_session(session_id)
    return {"status": "deleted"}

@app.post("/api/chat", response_model=ChatResponse, dependencies=[Depends(require_module("chat"))])
def chat(request: ChatRequest):
    session_id = request.session_id
    
    # Create session if not exists
    if not session_id:
        title = request.message[:30] + "..." if len(request.message) > 30 else request.message
        session_id = database.create_session(title)
    
    database.add_message(session_id, "user", request.message, request.images)
    
    # Build context for Ollama
    history = database.get_messages(session_id)
    # Convert to Ollama format
    ollama_messages = [select_system_prompt(request.mode)]
    citations: List[Dict[str, Any]] = []
    if request.mode == "tprm":
        rag_context, citations = build_rag_context(request.message, session_id, request.vendor, request.rag_k or 5)
        if rag_context:
            ollama_messages.append({
                "role": "system",
                "content": (
                    "Use only the following evidence to answer. "
                    "Provide a structured response with risk rating, impacted domains, and required controls. "
                    "Include a CITATIONS section listing each source in the format [DOC:<id> p.<start>-<end>].\n\n"
                    f"{rag_context}"
                )
            })
    for msg in history:
        m = {
            "role": msg["role"],
            "content": msg["content"],
        }
        if msg.get("images"):
            m["images"] = msg["images"]
        ollama_messages.append(m)
        
    try:
        # Call Ollama
        # Using stream=False for simplicity now, can upgrade to streaming later
        response = ollama.chat(model=request.model, messages=ollama_messages)
        ai_content = response['message']['content']
        
        if citations and "CITATIONS" not in ai_content:
            citation_lines = []
            for item in citations:
                citation_lines.append(f"- [DOC:{item.get('document_id')} p.{item.get('page_start')}-{item.get('page_end')}] {item.get('filename')}")
            ai_content = f"{ai_content}\n\nCITATIONS:\n" + "\n".join(citation_lines)
        message_id = database.add_message(session_id, "assistant", ai_content)
        if citations:
            database.add_citations(message_id, session_id, citations)
        
        return ChatResponse(
            session_id=session_id,
            message=Message(role="assistant", content=ai_content),
            citations=citations
        )
        
    except Exception as e:
        # Log error?
        print(f"Ollama Error: {e}")
        # Return error message to user but don't crash
        error_msg = "I encountered an error processing your request. Please ensure the model is available."
        database.add_message(session_id, "assistant", error_msg)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/documents/upload", dependencies=[Depends(require_module("tprm"))])
def upload_document(
    file: UploadFile = File(...),
    session_id: Optional[str] = Form(None),
    vendor: Optional[str] = Form(None),
    doc_type: Optional[str] = Form(None),
    access_scope: Optional[str] = Form(None)
):
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="File is required")
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are supported")
    if session_id:
        if not database.get_session(session_id):
            raise HTTPException(status_code=404, detail="Session not found")
    else:
        title = f"{vendor or 'TPRM'} document"
        session_id = database.create_session(title)
    doc_id = str(uuid.uuid4())
    access_scope = access_scope or "TPRM"
    safe_name = sanitize_filename(file.filename)
    doc_dir = os.path.join(get_upload_dir(), doc_id)
    os.makedirs(doc_dir, exist_ok=True)
    file_path = os.path.join(doc_dir, safe_name)
    with open(file_path, "wb") as buffer:
        buffer.write(file.file.read())
    database.create_document(doc_id, session_id, vendor, doc_type, access_scope, safe_name, file_path, "ingesting")
    try:
        reader = PdfReader(file_path)
        page_chunks = []
        page_count = len(reader.pages)
        for idx, page in enumerate(reader.pages):
            text = normalize_text(page.extract_text())
            page_number = idx + 1
            page_chunks.extend(chunk_page_text(text, page_number))
        embeddings = []
        for index, chunk in enumerate(page_chunks):
            content = chunk["content"]
            if not content:
                continue
            embedding = embed_text(content, os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text"))
            chunk_id = str(uuid.uuid4())
            embeddings.append(embedding)
            database.add_document_chunk(chunk_id, doc_id, session_id, vendor, index, chunk.get("page_start"), chunk.get("page_end"), content, chunk_id, embedding)
        database.update_document_status(doc_id, "ready", page_count=page_count, chunk_count=len(page_chunks))
    except Exception as e:
        database.update_document_status(doc_id, "error")
        raise HTTPException(status_code=500, detail=str(e))
    return database.get_document(doc_id)

@app.get("/api/documents", dependencies=[Depends(require_module("tprm"))])
def list_documents(session_id: Optional[str] = Query(None), vendor: Optional[str] = Query(None)):
    if not session_id and not vendor:
        raise HTTPException(status_code=400, detail="session_id or vendor is required")
    if session_id and not database.get_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return database.list_documents(session_id=session_id, vendor=vendor)

@app.delete("/api/documents/{doc_id}", dependencies=[Depends(require_module("tprm"))])
def delete_document(doc_id: str):
    doc = database.get_document(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    database.delete_document(doc_id)
    return {"status": "deleted"}

@app.get("/api/rag/metrics", dependencies=[Depends(require_module("tprm"))])
def rag_metrics(session_id: Optional[str] = Query(None)):
    return database.get_rag_metrics(session_id=session_id)

@app.post("/api/documents/retention", dependencies=[Depends(require_module("tprm"))])
def set_retention(days: int = Body(..., embed=True)):
    if days < 1:
        raise HTTPException(status_code=400, detail="Retention days must be positive")
    database.set_setting("retention_days", str(days))
    return {"status": "saved", "retention_days": days}

@app.post("/api/documents/purge", dependencies=[Depends(require_module("tprm"))])
def purge_documents(days: Optional[int] = Body(None, embed=True)):
    retention_days = days
    if retention_days is None:
        stored = database.get_setting("retention_days")
        retention_days = int(stored) if stored else 30
    purged = database.purge_retention(retention_days)
    return {"status": "purged", "documents_removed": purged}

# ==========================================
# TPRM Agentic Workflow API Endpoints
# ==========================================

class TPRMAssessmentRequest(BaseModel):
    vendor_name: str
    vendor_description: str = ""

import asyncio
from typing import Dict

async def execute_phase_1_categorization(assessment_id: str, vendor_name: str, vendor_description: str):
    """Actually categorizes the vendor risk tier using Ollama Qwen3-VL-8B/Qwen2.5-VL."""
    database.update_vendor_assessment_state(
        assessment_id, 
        phase=1, 
        state="TIER_PROCESSING",
        status_details="Waking up local Ollama models for semantic evaluation..."
    )
    
    prompt = f"""Evaluate the third-party risk tier and vendor type for vendor "{vendor_name}" based on the following context of their operations:
"{vendor_description}"

Rules for Risk Tier:
- If the vendor holds sensitive customer data (PII/PCI), operates core banking infrastructure, or is subject to SEBI/RBI regulations, tier is "High".
- If the vendor has operational/corporate network access without sensitive data, tier is "Medium".
- Otherwise, tier is "Low".

Rules for Vendor Type:
- If the service implies Cloud, Web App, or Software-as-a-Service, type is "SaaS".
- If the service implies Local Data Center, Physical Servers, or On-Premise, type is "On-Premise".
- If the service implies API Integration, Webhooks, or Code Libraries, type is "API Integration".
If unsure, default to "SaaS".

Output ONLY valid JSON in this exact format, with NO Markdown wrappers, NO code blocks, and NO extra text:
{{"tier": "High", "type": "SaaS"}}"""

    try:
        from sarvam_client import AsyncClient
        import os
        client = AsyncClient(host=os.getenv("OLLAMA_HOST", "http://localhost:11434"))
        
        # We try to use the configured model, default to qwen3:8b if not set
        target_model = os.getenv("OLLAMA_MODEL", "qwen3:8b") 
        
        database.update_vendor_assessment_state(
            assessment_id, 
            phase=1, 
            state="TIER_PROCESSING",
            status_details=f"Prompting '{target_model}' for logic reasoning..."
        )
        
        # Simple semaphore logic could be added here too if needed, 
        # but parser_module handles the heavy lifting usually.
        # Let's import the semaphore from parser_module to be consistent
        from parser_module import llm_semaphore
        
        async with llm_semaphore:
            response = await client.generate(model=target_model, prompt=prompt)
            
        # Parse the output
        output_text = response['response'].strip()
        assigned_tier = "Medium" # Default fallback
        vendor_type = "SaaS" # Default fallback
        
        try:
            # Clean possible markdown wrap
            json_str = output_text
            if "```json" in json_str: json_str = json_str.split("```json")[1].split("```")[0]
            elif "```" in json_str: json_str = json_str.split("```")[1].split("```")[0]
            
            # Find JSON boundaries just in case it added trailing text
            start = json_str.find('{')
            end = json_str.rfind('}') + 1
            if start != -1 and end != 0:
                json_str = json_str[start:end]
                
            parsed = json.loads(json_str)
            assigned_tier = parsed.get("tier", "Medium")
            vendor_type = parsed.get("type", "SaaS")
        except Exception as e:
            print(f"Error parsing Phase 1 json: {e}, raw: {output_text}")
            if "high" in output_text.lower(): assigned_tier = "High"
            elif "low" in output_text.lower(): assigned_tier = "Low"
            if "api" in output_text.lower(): vendor_type = "API Integration"
            elif "on-prem" in output_text.lower(): vendor_type = "On-Premise"
            
        database.update_vendor_assessment_state(
            assessment_id, 
            phase=1, 
            state="PENDING_TIER_APPROVAL",
            status_details=f"Evaluated Risk Tier: {assigned_tier} ({vendor_type}). Awaiting Human Review.",
            risk_tier=assigned_tier,
            vendor_type=vendor_type,
            impact_scores={"context": vendor_description}
        )
    except Exception as e:
        print(f"Error in Phase 1 categorization: {e}")
        # Fallback on error
        database.update_vendor_assessment_state(
            assessment_id, 
            phase=1, 
            state="PENDING_TIER_APPROVAL",
            status_details="System error during LLM generation. Defaulting to Medium. Awaiting Human Review.",
            risk_tier="Medium",
            impact_scores={"context": vendor_description}
        )

@app.post("/api/tprm/assessments", dependencies=[Depends(require_module("tprm"))])
def create_tprm_assessment(request: TPRMAssessmentRequest, background_tasks: BackgroundTasks):
    assessment_id = database.create_vendor_assessment(request.vendor_name)
    
    # Trigger Phase 1 logic asynchronously
    background_tasks.add_task(execute_phase_1_categorization, assessment_id, request.vendor_name, request.vendor_description)
    
    return {"id": assessment_id, "status": "TIER_PROCESSING"}

@app.get("/api/tprm/assessments", dependencies=[Depends(require_module("tprm"))])
def get_tprm_assessments():
    return database.get_vendor_assessments()

@app.get("/api/tprm/assessments/{assessment_id}", dependencies=[Depends(require_module("tprm"))])
def get_tprm_assessment(assessment_id: str):
    data = database.get_vendor_assessment_by_id(assessment_id)
    if not data:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return data

@app.get("/api/tprm/assessments/{assessment_id}/checklist", dependencies=[Depends(require_module("tprm"))])
def get_assessment_checklist(assessment_id: str):
    from fastapi.responses import FileResponse
    import os
    data = database.get_vendor_assessment_by_id(assessment_id)
    if not data:
        raise HTTPException(status_code=404, detail="Assessment not found")
        
    v_type = data.get("vendor_type", "SaaS")
    
    file_map = {
        "SaaS": "VRR Checklist - SaaS.xlsx",
        "On-Premise": "VRR Checklist - On-Prem.xlsx",
        "API Integration": "VRR Checklist - API Integration.xlsx"
    }
    
    filename = file_map.get(v_type, "VRR Checklist - SaaS.xlsx")
    filepath = os.path.join(os.path.dirname(__file__), "..", filename)
    
    if not os.path.exists(filepath):
        filepath = filename
    
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"Checklist template {filename} not found.")
        
    return FileResponse(filepath, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', filename=filename)

@app.delete("/api/tprm/assessments/{assessment_id}", dependencies=[Depends(require_module("tprm"))])
def delete_tprm_assessment(assessment_id: str):
    database.delete_vendor_assessment(assessment_id)
    return {"status": "deleted"}

@app.post("/api/tprm/assessments/{assessment_id}/stop", dependencies=[Depends(require_module("tprm"))])
def stop_tprm_assessment(assessment_id: str):
    data = database.get_vendor_assessment_by_id(assessment_id)
    if not data:
        raise HTTPException(status_code=404, detail="Assessment not found")
    
    # Just update state to STOPPED, backend tasks might need more complex cancellation logic
    # but for now, marking it stopped prevents further state transitions
    database.update_vendor_assessment_state(
        assessment_id, 
        phase=data.get('current_phase', 1), 
        state="STOPPED",
        status_details="Manually stopped by user"
    )
    return {"status": "stopped"}

@app.get("/api/tprm/assessments/{assessment_id}/export", dependencies=[Depends(require_module("tprm"))])
def export_tprm_assessment(assessment_id: str):
    data = database.get_vendor_assessment_by_id(assessment_id)
    if not data:
        raise HTTPException(status_code=404, detail="Assessment not found")
    
    # Construct a detailed report structure
    report = {
        "assessment_id": assessment_id,
        "vendor_name": data.get("vendor_name"),
        "risk_tier": data.get("risk_tier"),
        "overall_status": data.get("workflow_state"),
        "generated_at": datetime.datetime.now().isoformat(),
        "compliance_summary": {
            "compliant_controls": [],
            "non_compliant_controls": [],
            "pending_controls": []
        },
        "details": data
    }
    
    # Process internal score data if available to populate compliance summary
    internal_data = data.get("internal_score_data")
    if internal_data and isinstance(internal_data, dict):
        # This assumes internal_data has a structure we can parse. 
        # If it's just raw parsed excel data, we might need to interpret it.
        # For now, we'll pass the raw data and let the frontend format it, 
        # or do basic extraction if structure is known.
        pass

    return report

class TierApprovalRequest(BaseModel):
    risk_tier: str

@app.post("/api/tprm/assessments/{assessment_id}/approve-tier", dependencies=[Depends(require_module("tprm"))])
def approve_tier(assessment_id: str, request: TierApprovalRequest):
    # HITL Gate 1: Move from PENDING_TIER_APPROVAL to waiting for spreadsheet
    database.update_vendor_assessment_state(
        assessment_id, 
        phase=2, 
        state="AWAITING_SPREADSHEET", 
        risk_tier=request.risk_tier
    )
    return {"status": "approved", "tier": request.risk_tier}

import parser_module

@app.post("/api/tprm/assessments/{assessment_id}/upload-spreadsheet", dependencies=[Depends(require_module("tprm"))])
async def upload_spreadsheet(assessment_id: str, background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    # Phase 2: Accept xlsx, save it, trigger parser
    try:
        data = database.get_vendor_assessment_by_id(assessment_id)
        if not data:
            raise HTTPException(status_code=404, detail="Assessment not found")
        
        file_path = os.path.join(get_upload_dir(), f"{assessment_id}_{sanitize_filename(file.filename)}")
        with open(file_path, "wb") as buffer:
            buffer.write(await file.read())
            
        database.update_vendor_assessment_state(
            assessment_id, 
            phase=2, 
            state="PARSING_SPREADSHEET"
        )
        
        # Trigger async parsing process
        background_tasks.add_task(
            parser_module.parse_vendor_spreadsheet,
            assessment_id,
            file_path
        )
        
        return {"status": "uploaded", "file_path": file_path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

import recon_module

@app.post("/api/tprm/assessments/{assessment_id}/trigger-recon", dependencies=[Depends(require_module("tprm"))])
def trigger_recon(assessment_id: str, background_tasks: BackgroundTasks):
    # Phase 3 Override
    data = database.get_vendor_assessment_by_id(assessment_id)
    if not data:
        raise HTTPException(status_code=404, detail="Assessment not found")
        
    database.update_vendor_assessment_state(
        assessment_id, 
        phase=3, 
        state="CONDUCTING_RECON"
    )
    
    # Trigger isolated OSINT module asynchronously
    background_tasks.add_task(
        recon_module.trigger_async_recon, 
        assessment_id, 
        data["vendor_name"]
    )
    return {"status": "recon_initiated"}

@app.get("/api/tprm/assessments/{assessment_id}/draft-email", dependencies=[Depends(require_module("tprm"))])
def get_email_draft(assessment_id: str):
    # Phase 4 Review
    data = database.get_vendor_assessment_by_id(assessment_id)
    if not data:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return {"email_draft": data.get("email_draft", "")}

@app.post("/api/tprm/assessments/{assessment_id}/approve-email", dependencies=[Depends(require_module("tprm"))])
def approve_email(assessment_id: str):
    # HITL Gate 2: Approve and complete
    database.update_vendor_assessment_state(
        assessment_id, 
        phase=4, 
        state="COMPLETED"
    )
    # Dispatch via Outlook API (mocked for now)
    return {"status": "dispatched"}


# ==========================================
# Policy Generator Endpoints
# ==========================================
import policy_module
app.include_router(policy_module.router, dependencies=[Depends(require_module("policy"))])

# ==========================================
# RBAC Access Control Endpoints
# ==========================================
import rbac_module
app.include_router(rbac_module.router)

# ==========================================
# Code Scanning (Multi-Repo Agentic SAST) Endpoints
# Mounted under /api/code-scan via code_scan_module.router
# ==========================================
import code_scan_module
app.include_router(code_scan_module.router, dependencies=[Depends(require_module("code_scan"))])

# ==========================================
# EASM (External Attack Surface Management) Endpoints
# Mounted under /api/easm via easm_module.router
# ==========================================
import easm_module
app.include_router(easm_module.router, dependencies=[Depends(require_module("easm"))])

import bas_module
app.include_router(bas_module.router, dependencies=[Depends(require_module("bas"))])

# ==========================================
# Threat Modeling Endpoints
# Mounted under /api/threat-model via threat_model_module.router
# ==========================================
import threat_model_module
app.include_router(threat_model_module.router, dependencies=[Depends(require_module("threat_model"))])

# ==========================================
# Unified Vulnerability Dashboard Endpoints
# Mounted under /api/unified-dashboard via unified_dashboard_module.router
# ==========================================
import unified_dashboard_module
app.include_router(unified_dashboard_module.router, dependencies=[Depends(require_module("unified_dashboard"))])

import hashlib
import uuid

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/auth/login")
def auth_login(req: LoginRequest):
    if req.username != "caramella":
        raise HTTPException(status_code=401, detail="INVALID OPERATOR ID")
    
    # Secure SHA256 evaluation of provided passcode
    hashed_pw = hashlib.sha256(req.password.encode()).hexdigest()
    expected_hash = "47f0e069763e11d58c8cd7218ecd54ce8765ab94dda4cba03f0aab30a0c30437" # Hash for GRU29155
    
    if hashed_pw != expected_hash:
        raise HTTPException(status_code=401, detail="ACCESS DENIED: INVALID PASSCODE")
        
    token = uuid.uuid4().hex
    return {"token": token, "status": "authorized"}

# ==========================================
# AGENTIC VULNERABILITY MANAGEMENT
# ==========================================
import vuln_module

@app.get("/api/vuln/reports", dependencies=[Depends(require_module("vuln"))])
def get_vuln_reports():
    return database.get_vuln_reports()

@app.get("/api/vuln/reports/{report_id}", dependencies=[Depends(require_module("vuln"))])
def get_vuln_report_details(report_id: str):
    report = database.get_vuln_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Vuln report not found")
    findings = database.get_vuln_findings(report_id)
    return {
        "report": report,
        "findings": findings
    }

@app.post("/api/vuln/reports/upload", dependencies=[Depends(require_module("vuln"))])
async def upload_vuln_report(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    file_bytes = await file.read()
    report_id = await vuln_module.process_vuln_file(file_bytes, file.filename)

    # Fire-and-forget: trigger unified dashboard ingestion
    try:
        import unified_dashboard_module
        asyncio.create_task(unified_dashboard_module.trigger_ingestion('vuln_management', report_id))
    except Exception as e:
        import logging
        logging.getLogger("main").error(f"Unified dashboard ingestion hook failed: {e}")

    return {"status": "success", "report_id": report_id}

class VulnAnalyzeRequest(BaseModel):
    report_id: str

@app.post("/api/vuln/analyze", dependencies=[Depends(require_module("vuln"))])
def analyze_vuln_report(request: VulnAnalyzeRequest, background_tasks: BackgroundTasks):
    report = database.get_vuln_report(request.report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    background_tasks.add_task(vuln_module.augment_vuln_report_async, request.report_id)
    return {"status": "launched"}

import mobile_sast_module

def _compact_mobile_sast_metadata(scan_metadata: Any) -> Dict[str, Any]:
    metadata = scan_metadata if isinstance(scan_metadata, dict) else {}
    semgrep_summary = metadata.get("semgrep_summary") if isinstance(metadata.get("semgrep_summary"), dict) else {}
    mobsf_summary = metadata.get("mobsf_raw_summary") if isinstance(metadata.get("mobsf_raw_summary"), dict) else {}
    oxo_summary = metadata.get("oxo_raw_summary") if isinstance(metadata.get("oxo_raw_summary"), dict) else {}
    ios_binary_summary = metadata.get("ios_binary_summary") if isinstance(metadata.get("ios_binary_summary"), dict) else {}
    compact_semgrep = {
        "decompiled_ok": semgrep_summary.get("decompiled_ok"),
        "java_files_count": semgrep_summary.get("java_files_count"),
        "return_code": semgrep_summary.get("return_code"),
        "results_count": semgrep_summary.get("results_count"),
    }
    compact_mobsf = {
        "base_url_used": mobsf_summary.get("base_url_used"),
        "error": mobsf_summary.get("error"),
        "error_excerpt": mobsf_summary.get("error_excerpt"),
        "findings_emitted_total": mobsf_summary.get("findings_emitted_total"),
    }
    compact_oxo = {
        "scan_id": oxo_summary.get("scan_id"),
        "error": oxo_summary.get("error"),
        "run_return_code": oxo_summary.get("run_return_code"),
        "dump_return_code": oxo_summary.get("dump_return_code"),
        "records_read": oxo_summary.get("records_read"),
        "findings_emitted_total": oxo_summary.get("findings_emitted_total"),
    }
    compact_ios_binary = {
        "tools_available": ios_binary_summary.get("tools_available"),
        "encryption_hint": ios_binary_summary.get("encryption_hint"),
        "hardening_flags": ios_binary_summary.get("hardening_flags"),
        "linked_libraries_count": len(ios_binary_summary.get("linked_libraries") or []),
        "weak_crypto_markers": ios_binary_summary.get("weak_crypto_markers"),
        "weak_api_markers": ios_binary_summary.get("weak_api_markers"),
    }
    compact_semgrep = {key: value for key, value in compact_semgrep.items() if value is not None}
    compact_mobsf = {key: value for key, value in compact_mobsf.items() if value is not None}
    compact_oxo = {key: value for key, value in compact_oxo.items() if value is not None}
    compact_ios_binary = {key: value for key, value in compact_ios_binary.items() if value is not None}
    compact = {
        "platform": metadata.get("platform"),
        "artifact_type": metadata.get("artifact_type"),
        "triage_progress": metadata.get("triage_progress"),
        "triage_summary": metadata.get("triage_summary"),
        "triage_config": metadata.get("triage_config"),
        "engine_raw_counts": metadata.get("engine_raw_counts"),
        "mobsf_summary": compact_mobsf,
        "oxo_summary": compact_oxo,
        "semgrep_summary": compact_semgrep,
        "ios_binary_summary": compact_ios_binary,
    }
    return {key: value for key, value in compact.items() if value not in (None, {}, [])}


def _compact_mobile_sast_scan(scan: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": scan.get("id"),
        "filename": scan.get("filename"),
        "status": scan.get("status"),
        "phase": scan.get("phase"),
        "progress": scan.get("progress"),
        "status_details": scan.get("status_details"),
        "raw_findings_count": scan.get("raw_findings_count"),
        "unique_findings_count": scan.get("unique_findings_count"),
        "confirmed_findings_count": scan.get("confirmed_findings_count"),
        "false_positive_count": scan.get("false_positive_count"),
        "scan_metadata": _compact_mobile_sast_metadata(scan.get("scan_metadata")),
        "created_at": scan.get("created_at"),
        "updated_at": scan.get("updated_at"),
    }

@app.post("/api/mobile-sast/scan", dependencies=[Depends(require_module("mobile_sast"))])
async def start_mobile_sast_scan(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="Mobile artifact file is required")
    active_scan = next(
        (
            scan for scan in database.get_mobile_sast_scans()
            if scan.get("status") in {"INITIALIZED", "RUNNING", "STOPPING"}
        ),
        None,
    )
    if active_scan:
        raise HTTPException(
            status_code=409,
            detail=f"Another mobile scan is active ({active_scan.get('id')}). Stop it before starting a new scan.",
        )
    safe_name = sanitize_filename(file.filename)
    scan_work_dir = os.path.join(get_mobile_sast_upload_dir(), str(uuid.uuid4()))
    os.makedirs(scan_work_dir, exist_ok=True)
    payload = await file.read()
    detection = _detect_mobile_artifact(safe_name, payload)
    if detection.get("error"):
        raise HTTPException(status_code=400, detail=detection["error"])
    artifact_path = os.path.join(scan_work_dir, safe_name)
    with open(artifact_path, "wb") as f:
        f.write(payload)
    scan_id = database.create_mobile_sast_scan(safe_name, artifact_path)
    platform = detection.get("platform")
    artifact_type = detection.get("artifact_type")
    database.update_mobile_sast_scan(
        scan_id,
        status="INITIALIZED",
        phase="ARTIFACT_UPLOAD_VALIDATION",
        progress=5,
        status_details=f"{artifact_type.upper()} upload accepted and scan queued",
        scan_metadata={
            "file_size_bytes": len(payload),
            "platform": platform,
            "artifact_type": artifact_type,
            "source_mode": "binary",
        }
    )
    background_tasks.add_task(mobile_sast_module.execute_mobile_sast_pipeline, scan_id)
    return {"status": "initiated", "scan_id": scan_id}

@app.get("/api/mobile-sast/scans", dependencies=[Depends(require_module("mobile_sast"))])
def get_mobile_sast_scans():
    scans = database.get_mobile_sast_scans()
    return [_compact_mobile_sast_scan(scan) for scan in scans]

@app.get("/api/mobile-sast/scan/{scan_id}", dependencies=[Depends(require_module("mobile_sast"))])
def get_mobile_sast_scan(scan_id: str):
    data = database.get_mobile_sast_scan_by_id(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    data["scan_metadata"] = _compact_mobile_sast_metadata(data.get("scan_metadata"))
    data["findings"] = database.get_mobile_sast_findings(scan_id)
    return data

@app.get("/api/mobile-sast/scan/{scan_id}/report", dependencies=[Depends(require_module("mobile_sast"))])
def get_mobile_sast_report(scan_id: str):
    if not database.get_mobile_sast_scan_by_id(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return mobile_sast_module.build_live_report(scan_id)

@app.post("/api/mobile-sast/scan/{scan_id}/stop", dependencies=[Depends(require_module("mobile_sast"))])
def stop_mobile_sast_scan(scan_id: str):
    data = database.get_mobile_sast_scan_by_id(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    database.request_stop_mobile_sast_scan(scan_id)
    cancelled = mobile_sast_module.cancel_scan_execution(scan_id)
    model_released = mobile_sast_module.release_ollama_model_cache()
    database.update_mobile_sast_scan(
        scan_id,
        status="STOPPING",
        status_details="Stop requested by user. Pipeline will halt at next checkpoint.",
        phase=data.get("phase") or "LLM_TRIAGE"
    )
    return {"status": "stop_requested", "task_cancelled": cancelled, "model_released": model_released}

@app.delete("/api/mobile-sast/scan/{scan_id}", dependencies=[Depends(require_module("mobile_sast"))])
def delete_mobile_sast_scan(scan_id: str):
    data = database.get_mobile_sast_scan_by_id(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    database.request_stop_mobile_sast_scan(scan_id)
    mobile_sast_module.cancel_scan_execution(scan_id)
    mobile_sast_module.release_ollama_model_cache()
    artifact_path = data.get("apk_path")
    if artifact_path and os.path.exists(artifact_path):
        try:
            parent = os.path.dirname(artifact_path)
            if os.path.exists(parent):
                import shutil
                shutil.rmtree(parent, ignore_errors=True)
        except Exception:
            pass
    database.delete_mobile_sast_scan(scan_id)
    return {"status": "deleted"}

@app.get("/api/mobile-sast/scan/{scan_id}/status", dependencies=[Depends(require_module("mobile_sast"))])
async def mobile_sast_scan_status_stream(scan_id: str):
    if not database.get_mobile_sast_scan_by_id(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    terminal_states = {"COMPLETED", "FAILED", "STOPPED"}
    async def event_generator():
        last_payload = None
        while True:
            scan = database.get_mobile_sast_scan_by_id(scan_id)
            if not scan:
                payload = {"scan_id": scan_id, "status": "DELETED"}
                if payload != last_payload:
                    yield f"data: {json.dumps(payload)}\n\n"
                break
            payload = {
                "scan_id": scan_id,
                "status": scan.get("status"),
                "phase": scan.get("phase"),
                "progress": scan.get("progress"),
                "status_details": scan.get("status_details"),
                "raw_findings_count": scan.get("raw_findings_count"),
                "unique_findings_count": scan.get("unique_findings_count"),
                "confirmed_findings_count": scan.get("confirmed_findings_count"),
                "false_positive_count": scan.get("false_positive_count"),
                "scan_metadata": _compact_mobile_sast_metadata(scan.get("scan_metadata")),
            }
            if payload != last_payload:
                yield f"data: {json.dumps(payload)}\n\n"
                last_payload = payload
            if scan.get("status") in terminal_states:
                break
            await asyncio.sleep(1.0)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

# ==========================================
# MOBILE DAST (Ostorlab) ENDPOINTS
# ==========================================
import mobile_dast_module

def get_mobile_dast_upload_dir():
    return os.path.join(os.path.dirname(__file__), "mobile_dast_uploads")

@app.post("/api/mobile-dast/scan", dependencies=[Depends(require_module("mobile_dast"))])
async def start_mobile_dast_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    filename = file.filename or "unknown"
    # Auto-detect platform from file extension
    try:
        platform = mobile_dast_module.detect_platform(filename)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    payload = await file.read()
    if len(payload) < 1000:
        raise HTTPException(status_code=400, detail="File too small — corrupted or invalid")

    # Save file
    scan_id = str(uuid.uuid4())
    upload_dir = get_mobile_dast_upload_dir()
    os.makedirs(upload_dir, exist_ok=True)
    safe_name = sanitize_filename(filename)
    file_path = os.path.join(upload_dir, f"{scan_id}_{safe_name}")
    with open(file_path, "wb") as f:
        f.write(payload)

    # Create scan record
    database.create_mobile_dast_scan(scan_id, filename, file_path, platform)

    # Start pipeline in background thread with its own event loop
    import threading
    def _run_dast_pipeline():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(mobile_dast_module.execute_dast_pipeline(scan_id, file_path, filename))
        finally:
            loop.close()

    thread = threading.Thread(target=_run_dast_pipeline, daemon=True)
    thread.start()
    return {"status": "initiated", "scan_id": scan_id, "platform": platform}

@app.get("/api/mobile-dast/scans", dependencies=[Depends(require_module("mobile_dast"))])
def get_mobile_dast_scans():
    return database.get_mobile_dast_scans()

@app.get("/api/mobile-dast/scan/{scan_id}", dependencies=[Depends(require_module("mobile_dast"))])
def get_mobile_dast_scan(scan_id: str):
    data = database.get_mobile_dast_scan_by_id(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    data["findings"] = database.get_mobile_dast_findings(scan_id)
    return data

@app.get("/api/mobile-dast/scan/{scan_id}/report", dependencies=[Depends(require_module("mobile_dast"))])
def get_mobile_dast_report(scan_id: str):
    if not database.get_mobile_dast_scan_by_id(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = database.get_mobile_dast_findings(scan_id)
    scan = database.get_mobile_dast_scan_by_id(scan_id)
    return {
        "findings": findings,
        "summary": {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.get("risk_rating") == "Critical"),
            "high": sum(1 for f in findings if f.get("risk_rating") == "High"),
            "medium": sum(1 for f in findings if f.get("risk_rating") == "Medium"),
            "low": sum(1 for f in findings if f.get("risk_rating") == "Low"),
            "potentially": sum(1 for f in findings if f.get("risk_rating") == "Potentially"),
            "hardening": sum(1 for f in findings if f.get("risk_rating") == "Hardening"),
        },
        "scan_metadata": scan.get("scan_metadata"),
        "risk_rating": scan.get("risk_rating"),
    }

@app.post("/api/mobile-dast/scan/{scan_id}/stop", dependencies=[Depends(require_module("mobile_dast"))])
def stop_mobile_dast_scan(scan_id: str):
    data = database.get_mobile_dast_scan_by_id(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    database.request_stop_mobile_dast_scan(scan_id)
    database.update_mobile_dast_scan(
        scan_id,
        status="STOPPING",
        status_details="Stop requested by user. Pipeline will halt at next checkpoint.",
        phase=data.get("phase") or "SCAN_RUNNING"
    )
    return {"status": "stop_requested"}

@app.delete("/api/mobile-dast/scan/{scan_id}", dependencies=[Depends(require_module("mobile_dast"))])
def delete_mobile_dast_scan(scan_id: str):
    data = database.get_mobile_dast_scan_by_id(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    database.request_stop_mobile_dast_scan(scan_id)
    # Clean up uploaded file
    file_path = data.get("file_path")
    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
        except Exception:
            pass
    database.delete_mobile_dast_scan(scan_id)
    return {"status": "deleted"}

@app.get("/api/mobile-dast/scan/{scan_id}/status", dependencies=[Depends(require_module("mobile_dast"))])
async def mobile_dast_scan_status_stream(scan_id: str):
    if not database.get_mobile_dast_scan_by_id(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    terminal_states = {"COMPLETED", "FAILED", "STOPPED"}
    async def event_generator():
        last_payload = None
        while True:
            scan = database.get_mobile_dast_scan_by_id(scan_id)
            if not scan:
                payload = {"scan_id": scan_id, "status": "DELETED"}
                if payload != last_payload:
                    yield f"data: {json.dumps(payload)}\n\n"
                break
            # Include findings count for incremental updates
            findings = database.get_mobile_dast_findings(scan_id)
            finding_summary = {
                "total": len(findings),
                "critical": sum(1 for f in findings if f.get("risk_rating") == "Critical"),
                "high": sum(1 for f in findings if f.get("risk_rating") == "High"),
                "medium": sum(1 for f in findings if f.get("risk_rating") == "Medium"),
                "low": sum(1 for f in findings if f.get("risk_rating") == "Low"),
            }
            payload = {
                "scan_id": scan_id,
                "status": scan.get("status"),
                "phase": scan.get("phase"),
                "progress": scan.get("progress"),
                "status_details": scan.get("status_details"),
                "platform": scan.get("platform"),
                "risk_rating": scan.get("risk_rating"),
                "vulnerability_count": scan.get("vulnerability_count"),
                "ostorlab_scan_id": scan.get("ostorlab_scan_id"),
                "finding_summary": finding_summary,
                "latest_findings": [
                    {"title": f.get("title"), "risk_rating": f.get("risk_rating"), "short_description": f.get("short_description")}
                    for f in findings[-5:]  # Last 5 findings for live preview
                ],
            }
            if payload != last_payload:
                yield f"data: {json.dumps(payload)}\n\n"
                last_payload = payload
            if scan.get("status") in terminal_states:
                break
            await asyncio.sleep(2.0)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

# Connect React App (Static Files)
# This assumes the frontend build is located in a 'static' directory relative to this file
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

static_dir = os.path.join(os.path.dirname(__file__), "static")

if os.path.exists(static_dir):
    app.mount("/assets", StaticFiles(directory=os.path.join(static_dir, "assets")), name="assets")

    @app.get("/")
    async def serve_index():
        return FileResponse(os.path.join(static_dir, "index.html"))

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # Check if file exists (e.g. favicon)
        possible_file = os.path.join(static_dir, full_path)
        if os.path.exists(possible_file) and os.path.isfile(possible_file):
            return FileResponse(possible_file)
        # Fallback to index.html for SPA routing
        return FileResponse(os.path.join(static_dir, "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
