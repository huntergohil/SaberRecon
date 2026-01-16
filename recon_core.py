from datetime import datetime
from urllib.parse import urlparse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
import subprocess
import random
import string
import base64
import mimetypes

def build_data_uri_for_logo(logo_path: Path) -> str | None: 
  try: 
    data = logo_path.read_bytes() 
  except FileNotFoundError: 
    return None 

  mime, _ = mimetypes.guess_type(str(logo_path)) 
  if not mime: 
    mime = "image/png" 

  b64 = base64.b64encode(data).decode("ascii") 
  return f"data:{mime};base64,{b64}"

def detect_wildcard_length(domain: str) -> int | None:
    fake_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    url = f"https://{domain}/{fake_path}"
    out = run_cmd(["curl", "-s", "-o", "/dev/null", "-w", "%{size_download}", url], timeout=20).strip()
    try:
        return int(out)
    except:
        return None

def detect_wildcard_status(domain: str) -> int | None:
    fake_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    url = f"https://{domain}/{fake_path}"
    out = run_cmd(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", url], timeout=20).strip()
    try:
        return int(out)
    except:
        return None


def normalize_target(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        t = "https://" + t
    parsed = urlparse(t)
    domain = parsed.netloc or parsed.path
    return domain.strip().strip("/")


def run_cmd(args, timeout=90) -> str:
    try:
        out = subprocess.check_output(args, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode(errors="replace")
    except FileNotFoundError:
        return f"[!] Tool not installed: {args[0]}\n"
    except subprocess.TimeoutExpired:
        return f"[!] Timed out after {timeout}s: {' '.join(args)}\n"
    except subprocess.CalledProcessError as e:
        return f"[!] Error running: {' '.join(args)}\n{e.output.decode(errors='replace')}\n"


def build_tools(domain: str):
    url = f"https://{domain}"

    wild_len = detect_wildcard_length(domain)
    wild_code = detect_wildcard_status(domain)

    gobuster_args = ["gobuster", "dir", "-u", url, "-w", "./common.txt", "-f"]

    if wild_len is not None and wild_len > 0:
        gobuster_args += ["--exclude-length", str(wild_len)]
    else:
        if wild_code is not None and wild_code not in (404,):
            gobuster_args += ["-b", str(wild_code)]
        else:
            gobuster_args += ["-b", "404"]

    return [
        (["whois", domain.replace("www.", "")], "WHOIS Lookup"),
        (["nslookup", domain], "NSLookup"),
        (["dig", domain], "DIG DNS Info"),
        (["nmap", "-F", domain], "Nmap Fast Scan"),
        (["curl", "-I", url], "HTTP Headers (curl)"),
        (["whatweb", url], "WhatWeb Fingerprint"),
        (["subfinder", "-silent", "-d", domain], "Subdomain Enumeration (subfinder)"),
        (gobuster_args, "Gobuster Directory Scan"),
        (["wafw00f", url], "WAF Detection (WAFW00F)"),
    ]

def render_report_html(target: str, domain: str, sections: list[dict]) -> str:
    env = Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report_template.html")

    logo_data_uri = build_data_uri_for_logo(Path("static") / "SaberShieldLogoWithText.png")

    return template.render(
        target=target,
        domain=domain,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        sections=sections,
        logo_data_uri=logo_data_uri,
    )


def run_recon_and_write_html(target: str, output_html_path: Path, progress_cb=None) -> None:
    domain = normalize_target(target)
    if not domain:
        raise ValueError("Target is empty or invalid.")

    tools = build_tools(domain)
    total = len(tools)

    sections = []
    for i, (args, title) in enumerate(tools, start=1):
        if progress_cb:
            progress_cb({
                "percent": int(((i - 1) / total) * 100),
                "stage": f"Running: {title}",
                "current": i - 1,
                "total": total,
            })

        output = run_cmd(args, timeout=90)
        if title.startswith("Subdomain Enumeration") and not output.strip():
            output = "No subdomains found.\n"

        sections.append({"title": title, "command": " ".join(args), "output": output})

        if progress_cb:
            progress_cb({
                "percent": int((i / total) * 100),
                "stage": f"Completed: {title}",
                "current": i,
                "total": total,
            })

    html = render_report_html(target=target, domain=domain, sections=sections)
    output_html_path.write_text(html)

    if progress_cb:
        progress_cb({
            "percent": 100,
            "stage": "Done",
            "current": total,
            "total": total,
        })
