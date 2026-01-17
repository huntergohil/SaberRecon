from fastapi import FastAPI, Request, Form, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from datetime import datetime
import uuid
import re
import threading
from urllib.parse import urlparse
from datetime import datetime
from recon_core import run_recon_and_write_html, get_tools_list, get_tool, run_single_tool, render_report_html, safe_report_filename
from starlette.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, select_autoescape

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


DATA_DIR = Path("/data")
DATA_DIR.mkdir(parents=True, exist_ok=True)

SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9_.-]+$")

JOBS = {}
JOBS_LOCK = threading.Lock()

env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(["html", "xml"]),
)

@app.get("/tools", response_class=HTMLResponse)
def tools_list_page(request: Request):
    tools = get_tools_list()
    return templates.TemplateResponse(
        "tools_list.html",
        {"request": request, "tools": tools},
    )

@app.get("/tools/{tool_id}", response_class=HTMLResponse)
def tool_detail_page(request: Request, tool_id: str):
    try:
        tool = get_tool(tool_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Tool not found")

    return templates.TemplateResponse(
        "tool_detail.html",
        {"request": request, "tool_id": tool_id, "tool": tool},
    )
@app.post("/run-tool")
async def run_tool(request: Request):
    form = await request.form()
    form_dict = dict(form)

    tool_id = form_dict.get("tool_id")
    target = form_dict.get("target")

    if not tool_id or not target:
        return HTMLResponse("Missing tool_id or target", status_code=400)

    selected = {k: v for k, v in form_dict.items() if k not in ("tool_id", "target")}

    result = run_single_tool(target=target, tool_id=tool_id, selected=selected)

    html = render_report_html(
        target=result["target"],
        domain=result["domain"],
        sections=[result["section"]],
    )

    out_dir = Path("/data")
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{tool_id}-{datetime.now().strftime('%m-%d-%Y-%H%M')}.html"
    out_path = out_dir / filename
    out_path.write_text(html, encoding="utf-8")

    return RedirectResponse(url=f"/view/{filename}", status_code=303)


def normalize_domain_for_filename(target: str) -> str:
    t = target.strip()
    if "://" not in t:
        t = "https://" + t

    parsed = urlparse(t)
    host = parsed.netloc or parsed.path
    host = host.lower()
    
    if host.startswith("www."):
        host = host[4:]

    host = host.replace(".", "-")

    host = "".join(c for c in host if c.isalnum() or c == "-")

    return host or "target"


def timestamp_for_filename() -> str:
    return datetime.now().strftime("%m-%d-%Y-%H%M")


def safe_resolve_report(filename: str) -> Path:
    if not SAFE_NAME_RE.match(filename):
        raise ValueError("Invalid filename.")
    p = (DATA_DIR / filename).resolve()
    if not str(p).startswith(str(DATA_DIR.resolve()) + "/") and p != DATA_DIR.resolve():
        raise ValueError("Invalid path.")
    if not p.exists() or not p.is_file():
        raise FileNotFoundError("Report not found.")
    return p


def list_reports():
    items = []
    for p in sorted(DATA_DIR.glob("*.html"), key=lambda x: x.stat().st_mtime, reverse=True):
        st = p.stat()
        items.append(
            {
                "name": p.name,
                "size": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
    return items

def set_job(job_id: str, **kwargs):
    with JOBS_LOCK:
        JOBS.setdefault(job_id, {})
        JOBS[job_id].update(kwargs)

def run_job(job_id: str, target: str, filename: str):
    out_path = DATA_DIR / filename

    def progress_cb(payload):
        set_job(job_id, status="running", **payload)

    try:
        set_job(job_id, status="running", percent=0, stage="Starting...", current=0, total=0, filename=filename, target=target)
        run_recon_and_write_html(target=target, output_html_path=out_path, progress_cb=progress_cb)
        set_job(job_id, status="done", percent=100, stage="Done", filename=filename)
    except Exception as e:
        set_job(job_id, status="error", error=str(e), percent=100, stage="Error")

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/run", response_class=HTMLResponse)
def run_scan(request: Request, background_tasks: BackgroundTasks, target: str = Form(...)):
    job_id = uuid.uuid4().hex[:12]
    
    base = normalize_domain_for_filename(target)
    ts = timestamp_for_filename()
    
    filename = f"{base}-{ts}.html"
    
    set_job(job_id, status="queued", percent=0, stage="Queued", current=0, total=0, filename=filename, target=target)

    background_tasks.add_task(run_job, job_id, target, filename)

    return RedirectResponse(url=f"/progress/{job_id}", status_code=303)


@app.get("/progress/{job_id}", response_class=HTMLResponse)
def progress_page(request: Request, job_id: str):
    return templates.TemplateResponse("progress.html", {"request": request, "job_id": job_id})


@app.get("/api/status/{job_id}")
def job_status(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"status": "missing"}, status_code=404)
    return JSONResponse(job)


@app.get("/history", response_class=HTMLResponse)
def history(request: Request):
    reports = list_reports()
    return templates.TemplateResponse("history.html", {"request": request, "reports": reports})


@app.get("/view/{filename}", response_class=HTMLResponse)
def view_report(request: Request, filename: str):
    report_path = safe_resolve_report(filename)
    html = report_path.read_text(errors="replace")
    return HTMLResponse(content=html)


@app.get("/download/{filename}")
def download_report(filename: str):
    report_path = safe_resolve_report(filename)
    return FileResponse(report_path, media_type="text/html", filename=report_path.name)
