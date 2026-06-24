"""
CDNA SecureCRT Session Exporter
DNAC exporter infinite-retry
inventory, AP filtering, and SecureCRT session generation.

Author: Joe McSparin
Version: 3.1.0
Updated: 2026-02-26
"""

__author__ = "Joe McSparin"
__version__ = "3.1.0"
__updated__ = "2026-02-26"

import io
import re
import time
import uuid
import zipfile
import threading
import datetime as dt
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from ldap_auth import authenticate
from config import LDAP_SERVER
from functools import wraps

import requests
from requests.auth import HTTPBasicAuth
from flask import (
    Flask,
    request,
    session,
    redirect,
    url_for,
    jsonify,
    send_file,
    abort,
    render_template,
)
import smtplib
from email.message import EmailMessage

def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = session.get("user")
            if not user or user.get("role") != role:
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return wrapper
    return decorator
    
app = Flask(__name__)
app.secret_key = "098*()(sldfjoiwl"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # form posts only
app.config["SESSION_COOKIE_PATH"] = "/dna_crt"


# In-memory job store (note: jobs vanish on restart)
JOBS: Dict[str, Dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()


def now_ms() -> int:
    return int(dt.datetime.now().timestamp() * 1000)


def safe_hostname(host: str) -> str:
    if not host:
        return "unknown-host"
    host = host.replace("/", "")
    host = re.sub(r"\s+", "-", host.strip())
    return host or "unknown-host"


def backoff_sleep(attempt: int, base: float = 1.0, cap: float = 30.0) -> None:
    delay = min(cap, base * (2 ** attempt))
    time.sleep(delay)


def job_log(job_id: str, message: str) -> None:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job["logs"].append(message)
        job["updated_at"] = time.time()


def job_set(job_id: str, **kwargs) -> None:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job.update(kwargs)
        job["updated_at"] = time.time()


def job_get(job_id: str) -> Optional[Dict[str, Any]]:
    with JOBS_LOCK:
        return JOBS.get(job_id)


@dataclass
class RunConfig:
    dnac_host: str
    dnac_username: str
    dnac_password: str
    device_username: str = ""
    notify_email: str = ""
    verify_ssl: bool = False
    timeout_s: int = 10
    limit: int = 500
    offset_start: int = 1
    include_unified_aps: bool = False
    retries: int = 5
    throttle_sleep_s: int = 60


class DNACError(Exception):
    pass


def dnac_post_token(cfg: RunConfig, session: requests.Session) -> str:
    url = f"https://{cfg.dnac_host}/api/system/v1/auth/token"
    headers = {"content-type": "application/json"}
    r = session.post(
        url,
        auth=HTTPBasicAuth(cfg.dnac_username, cfg.dnac_password),
        headers=headers,
        verify=cfg.verify_ssl,
        timeout=cfg.timeout_s,
    )
    if r.status_code != 200:
        raise DNACError(f"Token request failed (HTTP {r.status_code}). Check DNAC host/creds.")
    data = r.json()
    token = data.get("Token")
    if not token:
        raise DNACError("Token response did not include 'Token'.")
    return token


def dnac_get_json(cfg: RunConfig, session: requests.Session, url: str, token: str,
                 params: Optional[dict] = None, job_id: Optional[str] = None) -> dict:
    """
    GET with retry/backoff + throttle handling + per-request timing logs.
    - Retries transient 429 / 5xx.
    - Does NOT retry non-429 4xx.
    - Logs status + elapsed time when job_id is provided.
    """
    headers = {"content-type": "application/json", "X-Auth-Token": token}
    jid = job_id
    last_exc: Optional[Exception] = None

    for attempt in range(cfg.retries):
        try:
            t0 = time.time()
            r = session.get(
                url,
                headers=headers,
                params=params,
                verify=cfg.verify_ssl,
                timeout=cfg.timeout_s,
            )
            elapsed = time.time() - t0

            if jid:
                job_log(jid, f"DNAC GET {r.status_code} {url} params={params} ({elapsed:.2f}s)")

            if r.status_code == 429:
                if jid:
                    job_log(jid, f"[throttle] HTTP 429. Sleeping {cfg.throttle_sleep_s}s then retrying: {url} params={params}")
                time.sleep(cfg.throttle_sleep_s)
                continue

            if 400 <= r.status_code < 500:
                raise DNACError(f"DNAC HTTP {r.status_code} for {url}. {r.text[:300]}")

            if 500 <= r.status_code < 600:
                if jid:
                    job_log(jid, f"[retry] HTTP {r.status_code} (attempt {attempt+1}/{cfg.retries}). Backing off then retrying: {url} params={params}")
                backoff_sleep(attempt)
                continue

            r.raise_for_status()
            return r.json()

        except DNACError as e:
            last_exc = e
            break
        except Exception as e:
            last_exc = e
            if jid:
                job_log(jid, f"[retry] Exception (attempt {attempt+1}/{cfg.retries}) {type(e).__name__}: {e}")
            backoff_sleep(attempt)

    raise DNACError(f"DNAC request failed after retries: {url} ({last_exc})")

def get_devices_offset_loop(cfg: RunConfig, session: requests.Session, token: str, job_id: str) -> List[dict]:
    devices: List[dict] = []
    offset = cfg.offset_start
    limit = cfg.limit

    while True:
        # Correct Intent inventory endpoint
        url = f"https://{cfg.dnac_host}/dna/intent/api/v1/network-device"
        params = {"offset": offset, "limit": limit}
        job_log(job_id, f"Fetching devices: offset={offset}, limit={limit}")
        data = dnac_get_json(cfg, session, url, token, params=params, job_id=job_id)
        batch = data.get("response", []) or []

        if not batch:
            break

        if not cfg.include_unified_aps:
            batch = [d for d in batch if d.get("family") != "Unified AP"]

        devices.extend(batch)
        offset += limit
        job_set(job_id, phase="fetching_devices", fetched_devices=len(devices))

    return devices


def build_crt_ini(ip: str, username: str) -> str:
    lines = []
    lines.append(f'S:"Username"={username}')
    lines.append('S:"Password V2"=')
    lines.append('D:"Session Password Saved"=00000000')
    lines.append('D:"Is Session"=00000001')
    lines.append('S:"Protocol Name"=SSH2')
    lines.append(f'S:"Hostname"={ip}')
    lines.append('D:"[SSH2] Port"=00000016')
    lines.append('S:"Emulation"=Xterm')
    lines.append('D:"Line Wrap"=00000001')
    lines.append('S:"Color Scheme"=Desert')
    return "\n".join(lines) + "\n"


def ensure_folder_with_folderdata(zf: zipfile.ZipFile, folder_path: str, created: set) -> None:
    if not folder_path.endswith("/"):
        folder_path += "/"
    if folder_path in created:
        return
    created.add(folder_path)
    zf.writestr(folder_path + "__FolderData__.ini", "")


def _get_location_from_inventory(dev: dict) -> Optional[str]:
    return dev.get("location") or dev.get("locationName") or None


def _device_detail_location(cfg: RunConfig, session: requests.Session, token: str, dev: dict) -> Optional[str]:
    url = f"https://{cfg.dnac_host}/dna/intent/api/v1/device-detail"

    dev_id = (dev.get("id") or "").strip()
    mac = (dev.get("macAddress") or "").strip()

    if dev_id:
        params = {"timestamp": now_ms(), "searchBy": dev_id, "identifier": "uuid"}
        try:
            detail = dnac_get_json(cfg, session, url, token, params=params)
            dev_details = detail.get("response") or {}
            loc = dev_details.get("location")
            if loc:
                return loc
        except Exception:
            pass

    if mac:
        params = {"timestamp": now_ms(), "searchBy": mac, "identifier": "macAddress"}
        try:
            detail = dnac_get_json(cfg, session, url, token, params=params)
            dev_details = detail.get("response") or {}
            loc = dev_details.get("location")
            if loc:
                return loc
        except Exception:
            pass

    return None


def generate_zip_hierarchical(cfg: RunConfig, session: requests.Session, devices: List[dict], token: str, job_id: str) -> bytes:
    total = len(devices)
    job_set(job_id, phase="building_sessions", total_devices=total, processed_devices=0)

    output = io.BytesIO()
    created_folders: set = set()
    root_folder = "CDNA-Session-Export/"

    # per-run cache
    detail_cache: Dict[str, str] = {}
    missing_loc_count = 0
    fallback_count = 0

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        readme_text = (
            "SecureCRT Session Import Instructions\n"
            "-------------------------------------\n"
            "QUICK INSTRUCTIONS BASED ON USUAL DEFAULTS\n"
            "1. Extract the contents of the zip folder to C:\\Users\\gev4293\\AppData\\Roaming\\VanDyke\\Config\\Sessions \n"
            "\n"
            "CHECK YOUR SETTINGS FIRST INSTRUCTIONS\n"
            "1. Open SecureCRT and select Options -> Global Options.\n"
            "2. Navigate to General -> Configuration Paths.\n"
            "3. Note the 'Configuration folder' path.\n"
            "4. Extract the contents of this ZIP into a folder.\n"
            "5. Copy the 'CDNA-Session-Export' folder into your SecureCRT Sessions directory.\n"
            "6. Restart SecureCRT and the sessions will appear.\n"
        )
        zf.writestr("readme.txt", readme_text)

        ensure_folder_with_folderdata(zf, root_folder, created_folders)

        for idx, dev in enumerate(devices, start=1):
            hostname = safe_hostname(dev.get("hostname"))
            mgmt_ip = dev.get("managementIpAddress") or ""

            if not hostname or not mgmt_ip:
                job_set(job_id, processed_devices=idx)
                continue

            location = _get_location_from_inventory(dev)
            if not location:
                missing_loc_count += 1
                dev_key = (dev.get("id") or dev.get("macAddress") or hostname)
                if dev_key in detail_cache:
                    location = detail_cache[dev_key]
                else:
                    loc = _device_detail_location(cfg, session, token, dev)
                    if loc:
                        location = loc
                        detail_cache[dev_key] = loc
                        fallback_count += 1

            site_building_path = "Unassigned"
            if location:
                if location.startswith("Global/"):
                    location = location[7:].strip()
                site_building_path = location or "Unassigned"

            parts = [p for p in site_building_path.split("/") if p]
            current_folder = root_folder
            for part in parts:
                current_folder = current_folder + part + "/"
                ensure_folder_with_folderdata(zf, current_folder, created_folders)

            session_folder = root_folder + ("/".join(parts) + "/" if parts else "")
            ensure_folder_with_folderdata(zf, session_folder, created_folders)

            ini_text = build_crt_ini(mgmt_ip, cfg.device_username)
            zf.writestr(session_folder + f"{hostname}.ini", ini_text)

            if idx % 50 == 0:
                job_log(job_id, f"Processed {idx}/{total}. MissingLoc={missing_loc_count}, FallbackUsed={fallback_count}")
            job_set(job_id, processed_devices=idx)

        job_log(job_id, f"Completed. MissingLoc={missing_loc_count}, FallbackUsed={fallback_count}")

    output.seek(0)
    return output.read()


def send_completion_email(to_addr: str, job_id: str, success: bool):
    msg = EmailMessage()
    msg["Subject"] = f"DNA CRT Job {job_id} Completed"
    msg["From"] = "dna-crt@mhshealth.com"
    msg["To"] = to_addr

    status_text = "completed successfully" if success else "finished with errors"
    download_url = f"http://10.196.227.112/dna_crt/job/{job_id}"

    msg.set_content(
        f"Your DNA CRT job has {status_text}.\n\n"
        f"You can download the results here:\n"
        f"{download_url}\n\n"
        f"Job ID: {job_id}\n"
        f"Timestamp: (server time)\n\n"
        f"This is an automated message."
    )

    with smtplib.SMTP("smtp-gw.ftw.medcity.net", 25) as smtp:
        smtp.send_message(msg)


def send_starting_email(to_addr: str, job_id: str):
    msg = EmailMessage()
    msg["Subject"] = f"DNA CRT Job {job_id} Started"
    msg["From"] = "dna-crt@mhshealth.com"
    msg["To"] = to_addr

    download_url = f"http://10.196.227.112/dna_crt/job/{job_id}"
    msg.set_content(
        "Your DNA CRT job has started.\n\n"
        f"You can check the status of your job here:\n{download_url}\n\n"
        f"Job ID: {job_id}\n\n"
        "This is an automated message."
    )

    with smtplib.SMTP("smtp-gw.ftw.medcity.net", 25) as smtp:
        smtp.send_message(msg)


def run_job(job_id: str, cfg: RunConfig) -> None:
    session = requests.Session()
    try:
        job_log(job_id, "Requesting DNAC token…")
        token = dnac_post_token(cfg, session)
        job_log(job_id, "Token OK. Fetching device inventory…")

        devices = get_devices_offset_loop(cfg, session, token, job_id)
        if not devices:
            raise DNACError("No devices returned from DNAC.")

        job_log(job_id, f"Inventory collected: {len(devices)} devices. Building SecureCRT sessions…")
        zip_bytes = generate_zip_hierarchical(cfg, session, devices, token, job_id)

        job_set(job_id, phase="done", done=True, zip_bytes=zip_bytes)
        job_log(job_id, "Done. ZIP is ready for download.")

        job_state = job_get(job_id)
        success = bool(job_state and job_state.get("phase") == "done")

        if cfg.notify_email:
            try:
                send_completion_email(cfg.notify_email, job_id, success)
            except Exception as e:
                job_log(job_id, f"[warn] Failed to send completion email: {e}")

    except Exception as e:
        job_set(job_id, phase="error", done=True, error=str(e))
        job_log(job_id, f"[error] {e}")


@app.get("/")
def root():
    return redirect("/dna_crt/home")


@app.route("/dna_crt/home")
@role_required("authorized")
def home():
    # Central landing page after login
    return redirect("/dna_crt/start")


@app.route('/dna_crt/start', methods=['GET', 'POST'])
@role_required("authorized")
def start():
    # GET → show main UI
    if request.method == 'GET':
        return render_template("index.html")

    # POST → start job
    dnac_host = (request.form.get("dnac_host") or "").strip()
    dnac_username = (request.form.get("dnac_username") or "").strip()
    dnac_password = (request.form.get("dnac_password") or "").strip()
    device_username = (request.form.get("device_username") or "").strip()
    notify_email = (request.form.get("notify_email") or "").strip()

    if not dnac_host or not dnac_username or not dnac_password:
        abort(400, "Missing required fields.")

    cfg = RunConfig(
        dnac_host=dnac_host,
        dnac_username=dnac_username,
        dnac_password=dnac_password,
        device_username=device_username,
        notify_email=notify_email,
        verify_ssl=bool(request.form.get("verify_ssl")),
        timeout_s=int(request.form.get("timeout_s") or 10),
        retries=int(request.form.get("retries") or 5),
        throttle_sleep_s=int(request.form.get("throttle_sleep_s") or 60),
        limit=int(request.form.get("limit") or 500),
        offset_start=int(request.form.get("offset_start") or 1),
        include_unified_aps=bool(request.form.get("include_unified_aps")),
    )

    job_id = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id,
            "phase": "queued",
            "done": False,
            "error": None,
            "logs": [],
            "created_at": time.time(),
            "updated_at": time.time(),
            "fetched_devices": 0,
            "total_devices": None,
            "processed_devices": 0,
            "zip_bytes": None,
        }

    if cfg.notify_email:
        try:
            send_starting_email(cfg.notify_email, job_id)
        except Exception as e:
            job_log(job_id, f"[warn] Failed to send starting email: {e}")

    t = threading.Thread(target=run_job, args=(job_id, cfg), daemon=True)
    t.start()

    return redirect(url_for("job_view", job_id=job_id))


@app.get("/dna_crt/job/<job_id>")
@role_required("authorized")
def job_view(job_id: str):
    if not job_get(job_id):
        abort(404)
    return render_template("job.html", job_id=job_id)


@app.get("/dna_crt/api/job/<job_id>")
@role_required("authorized")
def job_api(job_id: str):
    job = job_get(job_id)
    if not job:
        abort(404)
    data = {
        "id": job["id"],
        "phase": job.get("phase"),
        "done": job.get("done"),
        "error": job.get("error"),
        "logs": job.get("logs", [])[-400:],
        "fetched_devices": job.get("fetched_devices"),
        "total_devices": job.get("total_devices"),
        "processed_devices": job.get("processed_devices"),
    }
    return jsonify(data)


@app.get("/dna_crt/download/<job_id>")
@role_required("authorized")
def download(job_id: str):
    job = job_get(job_id)
    if not job:
        abort(404)
    if not job.get("done") or job.get("error") or not job.get("zip_bytes"):
        abort(409, "Job not completed.")
    buf = io.BytesIO(job["zip_bytes"])
    buf.seek(0)
    filename = "CDNA-Session-Export.zip"
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=filename)


@app.route('/dna_crt/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = authenticate(username, password)

        if user:
            session['user'] = user
            return redirect("/dna_crt/home")
        else:
            return render_template('login.html', error="Invalid credentials or unauthorized")

    return render_template('login.html')


@app.route('/dna_crt/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dna_crt/userinfo')
@role_required("authorized")
def userinfo():
    return {
        "name": session["user"]["name"],
        "email": session["user"]["email"],
        "username": session["user"]["username"]
    }


    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
