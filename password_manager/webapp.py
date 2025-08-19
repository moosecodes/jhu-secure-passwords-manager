'''webapp.py'''
from __future__ import annotations
import os
import secrets
from pathlib import Path
from cryptography.exceptions import InvalidTag
from flask import Flask, request, redirect, url_for, session, render_template_string, flash
from .vault_service import VaultService

# --- Config ---
VAULT_DEFAULT = Path("data/test.vault.json")
APP_SECRET = os.environ.get("SPM_SECRET", "dev-secret-change-me")  # set in env for real use

app = Flask(__name__)
app.secret_key = APP_SECRET
SESS_MASTERS: dict[str, str] = {}  # in-memory master storage per session id (single-user dev only)

def sid() -> str:
    if "sid" not in session:
        session["sid"] = secrets.token_hex(16)
    return session["sid"]

def get_svc() -> VaultService:
    m = SESS_MASTERS.get(sid())
    vf = Path(session.get("vault_file") or VAULT_DEFAULT)
    if not m:
        raise RuntimeError("Not authenticated.")
    svc = VaultService(vf, m)
    svc.load()
    return svc

BASE = """
<!doctype html>
<html lang="en" data-bs-theme="light">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootswatch@5.3.3/dist/darkly/bootstrap.min.css" rel="stylesheet">
<link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}">
<link rel="stylesheet" href="{{ url_for('static', filename='css/theme.css') }}?v=3">

<!-- Google Fonts: Inter + Figtree -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Figtree:wght@400;500;600&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">

<title>Secure Password Manager</title>
</head>
<body>
<nav class="navbar navbar-dark" style="background:#0b1220">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('vault') }}">🔐 Password Manager</a>
    <div>
      {% if session.get('vault_file') %}<span class="me-3 small text-secondary">{{ session.get('vault_file') }}</span>{% endif %}
      <a class="btn btn-sm btn-light" href="{{ url_for('logout') }}">Logout</a>
    </div>
  </div>
</nav>
<div class="container my-4" style="max-width: 980px;">
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="alert alert-info">{{ messages[0] }}</div>
    {% endif %}
  {% endwith %}
  {{ body|safe }}
</div>
</body></html>
"""

@app.route("/health")
def health():
    return {
        "cwd": str(Path.cwd()),
        "exists": Path(session.get("vault_file","data/test.vault.json")).exists(),
        "vault_env": session.get("vault_file","(unset)")
    }, 200

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        master = request.form.get("master","")
        vault_in = request.form.get("vault_file") or str(VAULT_DEFAULT)
        vault_file = Path(vault_in)
        try:
            if not vault_file.exists():
                raise FileNotFoundError(f"Vault not found: {vault_file.resolve()}")
            svc = VaultService(vault_file, master)
            svc.load()  # validate master + file
        except InvalidTag:
            app.logger.exception("Unlock failed: wrong master or corrupted file")
            flash("Unlock failed: wrong master password or file corrupted.")
            body = render_template_string(LOGIN_FORM)
            return render_template_string(BASE, body=body)
        except Exception as e:
            app.logger.exception("Unlock failed: %s", e)
            flash(f"Unlock failed: {e}")
            body = render_template_string(LOGIN_FORM)
            return render_template_string(BASE, body=body)
        session["vault_file"] = str(vault_file)
        SESS_MASTERS[sid()] = master
        return redirect(url_for("vault"))
    body = render_template_string(LOGIN_FORM)
    return render_template_string(BASE, body=body)

LOGIN_FORM = """
<div class="card p-4">
  <h5 class="mb-3">Unlock Vault</h5>
  <form method="post">
    <div class="mb-3">
      <label class="form-label">Vault file</label>
      <input class="form-control" name="vault_file" value="{{ session.get('vault_file','data/test.vault.json') }}">
      <div class="form-text text-secondary">Default: data/test.vault.json</div>
    </div>
    <div class="mb-3">
      <label class="form-label">Master password</label>
      <input class="form-control" type="password" name="master" placeholder="••••••••">
    </div>
    <button class="btn btn-primary">Unlock</button>
  </form>
</div>
"""

@app.route("/logout")
def logout():
    SESS_MASTERS.pop(sid(), None)
    session.clear()
    flash("Logged out.")
    return redirect(url_for("index"))

@app.route("/vault")
def vault():
    try:
        svc = get_svc()
    except Exception:
        return redirect(url_for("index"))
    q = request.args.get("q") or None
    tag = request.args.get("tag") or None
    entries = svc.list_entries(query=q, tag=tag)
    body = render_template_string(VAULT_LIST, entries=entries, q=q or "", tag=tag or "")
    return render_template_string(BASE, body=body)

VAULT_LIST = """
<div class="d-flex justify-content-between align-items-center mb-3">
  <form class="d-flex" method="get" action="{{ url_for('vault') }}">
    <input class="form-control me-2" name="q" value="{{ q }}" placeholder="Search site or username">
    <input class="form-control me-2" name="tag" value="{{ tag }}" placeholder="Filter by tag">
    <button class="btn btn-outline-light">Search</button>
  </form>
  <a class="btn btn-primary" href="{{ url_for('add') }}">+ Add Entry</a>
</div>
<div class="card p-0">
<table class="table table-dark table-striped mb-0">
  <thead><tr><th>Site</th><th>Username</th><th>Tags</th><th>Actions</th></tr></thead>
  <tbody>
  {% for e in entries %}
    <tr>
      <td>{{ e.site if e.site else e["site"] }}</td>
      <td>{{ e.username if e.username else e["username"] }}</td>
      <td>{{ ",".join(e.get("tags", [])) }}</td>
      <td class="text-nowrap">
        <a class="btn btn-sm btn-outline-light" href="{{ url_for('show', entry_id=e['id']) }}">View</a>
        <a class="btn btn-sm btn-outline-light" href="{{ url_for('edit', entry_id=e['id']) }}">Edit</a>
        <a class="btn btn-sm btn-outline-light" href="{{ url_for('rotate', entry_id=e['id']) }}">Rotate</a>
        <a class="btn btn-sm btn-outline-light" href="{{ url_for('delete', entry_id=e['id']) }}">Delete</a>
      </td>
    </tr>
  {% endfor %}
  {% if not entries %}<tr><td colspan="4" class="text-center text-secondary py-4">No entries.</td></tr>{% endif %}
  </tbody>
</table>
</div>
"""

@app.route("/add", methods=["GET","POST"])
def add():
    try:
        svc = get_svc()
    except Exception:
        return redirect(url_for("index"))
    if request.method == "POST":
        site = request.form.get("site","").strip()
        username = request.form.get("username","").strip()
        url = request.form.get("url") or None
        notes = request.form.get("notes") or None
        tags = [t.strip() for t in (request.form.get("tags","")).split(",") if t.strip()]
        gen = request.form.get("gen") == "on"
        if gen:
            e = svc.add_entry(site, username, password=None, url=url, notes=notes, tags=tags)
            svc.rotate_password(e["id"], length=int(request.form.get("length","16")))
        else:
            pw = request.form.get("password","")
            svc.add_entry(site, username, password=pw, url=url, notes=notes, tags=tags)
        flash("Entry added.")
        return redirect(url_for("vault"))
    body = render_template_string(FORM_ADD)
    return render_template_string(BASE, body=body)

FORM_ADD = """
<div class="card p-4">
  <h5 class="mb-3">Add Entry</h5>
  <form method="post">
    <div class="row g-3">
      <div class="col-md-6"><label class="form-label">Site</label><input class="form-control" name="site" required></div>
      <div class="col-md-6"><label class="form-label">Username</label><input class="form-control" name="username" required></div>
      <div class="col-md-6"><label class="form-label">URL</label><input class="form-control" name="url"></div>
      <div class="col-md-6"><label class="form-label">Tags (comma)</label><input class="form-control" name="tags"></div>
      <div class="col-12"><label class="form-label">Notes</label><textarea class="form-control" name="notes"></textarea></div>
    </div>
    <hr>
    <div class="form-check form-switch mb-2">
      <input class="form-check-input" type="checkbox" id="gen" name="gen" checked>
      <label class="form-check-label" for="gen">Auto-generate password</label>
    </div>
    <div id="genRow" class="row g-3">
      <div class="col-md-3"><label class="form-label">Length</label><input class="form-control" name="length" value="16"></div>
    </div>
    <div id="manualRow" class="mb-3" style="display:none;">
      <label class="form-label">Password</label><input class="form-control" name="password">
    </div>
    <button class="btn btn-primary">Save</button>
    <a class="btn btn-outline-light" href="{{ url_for('vault') }}">Cancel</a>
  </form>
</div>
<script>
document.getElementById('gen').addEventListener('change', (e)=>{
  document.getElementById('genRow').style.display = e.target.checked ? '' : 'none';
  document.getElementById('manualRow').style.display = e.target.checked ? 'none' : '';
});
</script>
"""

@app.route("/show/<entry_id>")
def show(entry_id):
    try: svc = get_svc()
    except Exception: return redirect(url_for("index"))
    e = svc.get_entry(entry_id=entry_id)
    if not e:
        flash("Not found."); return redirect(url_for("vault"))
    body = render_template_string(VIEW_ENTRY, e=e)
    return render_template_string(BASE, body=body)

VIEW_ENTRY = """
<div class="card p-4">
  <h5 class="mb-3">{{ e['site'] }} — {{ e['username'] }}</h5>
  <div class="mb-2"><strong>Password:</strong> <code>{{ e['password'] }}</code></div>
  <div class="mb-2"><strong>URL:</strong> {{ e.get('url') or '-' }}</div>
  <div class="mb-2"><strong>Tags:</strong> {{ ",".join(e.get("tags", [])) or "-" }}</div>
  <div class="mb-2"><strong>Notes:</strong> {{ e.get("notes") or "-" }}</div>
  <div class="mb-2"><strong>Updated:</strong> {{ e.get("updated_at") }}</div>
  <a class="btn btn-outline-light" href="{{ url_for('vault') }}">Back</a>
  <a class="btn btn-primary" href="{{ url_for('edit', entry_id=e['id']) }}">Edit</a>
</div>
"""

@app.route("/edit/<entry_id>", methods=["GET","POST"])
def edit(entry_id):
    try: svc = get_svc()
    except Exception: return redirect(url_for("index"))
    e = svc.get_entry(entry_id=entry_id)
    if not e:
        flash("Not found."); return redirect(url_for("vault"))
    if request.method == "POST":
        site = request.form.get("site",""); user = request.form.get("username","")
        url = request.form.get("url") or None; notes = request.form.get("notes") or None
        tags = [t.strip() for t in (request.form.get("tags","")).split(",") if t.strip()]
        if request.form.get("rotate") == "on":
            svc.rotate_password(entry_id, length=int(request.form.get("length","16")))
        elif request.form.get("password"):
            svc.update_entry(entry_id, password=request.form.get("password"), site=site, username=user, url=url, notes=notes, tags=tags)
        else:
            svc.update_entry(entry_id, site=site, username=user, url=url, notes=notes, tags=tags)
        flash("Updated.")
        return redirect(url_for("show", entry_id=entry_id))
    body = render_template_string(FORM_EDIT, e=e)
    return render_template_string(BASE, body=body)

FORM_EDIT = """
<div class="card p-4">
  <h5 class="mb-3">Edit Entry</h5>
  <form method="post">
    <div class="row g-3">
      <div class="col-md-6"><label class="form-label">Site</label><input class="form-control" name="site" value="{{ e['site'] }}"></div>
      <div class="col-md-6"><label class="form-label">Username</label><input class="form-control" name="username" value="{{ e['username'] }}"></div>
      <div class="col-md-6"><label class="form-label">URL</label><input class="form-control" name="url" value="{{ e.get('url','') }}"></div>
      <div class="col-md-6"><label class="form-label">Tags (comma)</label><input class="form-control" name="tags" value="{{ ','.join(e.get('tags',[])) }}"></div>
      <div class="col-12"><label class="form-label">Notes</label><textarea class="form-control" name="notes">{{ e.get('notes','') }}</textarea></div>
    </div>
    <hr>
    <div class="form-check form-switch mb-2">
      <input class="form-check-input" type="checkbox" id="rotate" name="rotate">
      <label class="form-check-label" for="rotate">Rotate password</label>
    </div>
    <div id="rotRow" class="row g-3" style="display:none;">
      <div class="col-md-3"><label class="form-label">New length</label><input class="form-control" name="length" value="16"></div>
    </div>
    <div class="mb-3">
      <label class="form-label">Or set specific password</label>
      <input class="form-control" name="password" placeholder="Leave blank to keep current">
    </div>
    <button class="btn btn-primary">Save</button>
    <a class="btn btn-outline-light" href="{{ url_for('show', entry_id=e['id']) }}">Cancel</a>
  </form>
</div>
<script>
document.getElementById('rotate').addEventListener('change', (e)=>{
  document.getElementById('rotRow').style.display = e.target.checked ? '' : 'none';
});
</script>
"""

@app.route("/rotate/<entry_id>")
def rotate(entry_id):
    try: svc = get_svc()
    except Exception: return redirect(url_for("index"))
    svc.rotate_password(entry_id)
    flash("Password rotated.")
    return redirect(url_for("show", entry_id=entry_id))

@app.route("/delete/<entry_id>")
def delete(entry_id):
    try: svc = get_svc()
    except Exception: return redirect(url_for("index"))
    ok = svc.delete_entry(entry_id)
    flash("Deleted." if ok else "Not found.")
    return redirect(url_for("vault"))
