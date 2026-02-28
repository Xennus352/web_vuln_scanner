import os
import sqlite3
from flask import Flask, request, redirect, url_for, session, render_template_string

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vuln_lab.db")

app = Flask(__name__)
app.secret_key = "dev-lab-secret-key"

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# --- UI COMPONENTS (Using double-braces to avoid f-string conflicts) ---
HEADER = """
<head>
  <meta charset="utf-8" />
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Fira+Code&family=Inter:wght@400;700&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Inter', sans-serif; background-color: #0f172a; color: #f8fafc; }
    .mono { font-family: 'Fira Code', monospace; }
    .glass { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); }
  </style>
</head>
"""

NAV = """
<nav class="border-b border-slate-800 p-4 mb-8 glass">
  <div class="max-w-5xl mx-auto flex justify-between items-center">
    <a href="/" class="text-xl font-bold text-sky-400 mono">GENESIS_LAB_v1.0</a>
    <div class="space-x-6 text-sm text-slate-400">
      <a href="/login" class="hover:text-sky-400">SQLi</a>
      <a href="/dashboard" class="hover:text-sky-400">XSS</a>
      <a href="/profile?id=1" class="hover:text-sky-400">IDOR</a>
    </div>
  </div>
</nav>
"""

LOGIN_PAGE = HEADER + NAV + """
<div class="flex items-center justify-center p-4">
  <div class="glass p-8 rounded-2xl w-full max-w-md border border-slate-700">
    <h2 class="text-2xl font-bold mb-6 text-center text-sky-400 mono">GATEWAY_AUTH</h2>
    
    {% if message %}
    <div class="mb-6 p-4 rounded-xl border mono text-xs 
        {% if status == 'error' %} bg-red-500/10 border-red-500 text-red-400 
        {% else %} bg-sky-500/10 border-sky-500 text-sky-400 {% endif %}">
      <div class="font-bold mb-1">
        {% if status == 'error' %}[!] SECURITY ALERT{% else %}[i] SYSTEM INFO{% endif %}
      </div>
      <p>{{ message }}</p>
    </div>
    {% endif %}

    <form method="POST" class="space-y-4">
      <input name="username" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-white outline-none focus:border-sky-500" placeholder="Username" />
      <input type="password" name="password" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-white outline-none focus:border-sky-500" placeholder="Password" />
      <button type="submit" class="w-full bg-sky-500 text-slate-900 font-bold py-3 rounded-lg hover:bg-sky-400">VERIFY_IDENTITY</button>
    </form>
  </div>
</div>
"""

@app.route("/")
def home():
    return render_template_string(HEADER + NAV + "<div class='p-10 text-center'><h1 class='text-3xl font-bold'>Lab Ready</h1><p class='text-slate-400'>Navigate to a module to begin.</p></div>")

@app.route("/login", methods=["GET", "POST"])
def login():
    message, status = "", "info"
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        # SQLi Vulnerable query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(query)
            user = cur.fetchone()
        except Exception as exc:
            conn.close()
            return render_template_string(LOGIN_PAGE, message=f"SQL_ERROR: {exc}", status="error")
        conn.close()

        if user:
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        
        message, status = "AUTH_FAILED: Access Denied.", "error"

    return render_template_string(LOGIN_PAGE, message=message, status=status)

@app.route("/dashboard")
def dashboard():
    query = request.args.get("q", "")
    DASHBOARD_HTML = HEADER + NAV + f"""
    <div class="max-w-4xl mx-auto p-4 glass rounded-2xl border border-slate-700">
      <h2 class="text-2xl font-bold mb-4">Dashboard</h2>
      <div class="bg-slate-900 p-4 rounded-lg mono text-sm">
        <p class="text-slate-500">Search results for: <span class="text-white">{{{{ query|safe }}}}</span></p>
      </div>
    </div>"""
    return render_template_string(DASHBOARD_HTML, query=query)

@app.route("/profile")
def profile():
    requested_id = request.args.get("id", "")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username, secret_bio FROM users WHERE id = ?", (requested_id,))
    user = cur.fetchone()
    conn.close()
    
    PROFILE_HTML = HEADER + NAV + """
    <div class="max-w-xl mx-auto glass p-8 rounded-2xl border border-slate-700">
      {% if user %}
        <h2 class="text-2xl font-bold mb-4">{{ user.username }}</h2>
        <div class="p-4 bg-black/30 rounded-lg text-emerald-400 mono text-sm">{{ user.secret_bio }}</div>
      {% else %}
        <p class="text-red-400">User Not Found</p>
      {% endif %}
    </div>"""
    return render_template_string(PROFILE_HTML, user=user)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)