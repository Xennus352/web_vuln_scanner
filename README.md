# Web Vulnerability Scanner

A simple **web-based vulnerability scanner** built with **Flask**, **Playwright**, and **Python**.  
It can crawl websites, detect **XSS**, **SQL Injection**, and missing **security headers**, all through a **single-page web UI**. Designed for testing your **own lab environments** or vulnerable apps like **DVWA**, **Juice Shop**, or **Altoro Mutual**.  

---

## Features

- Crawl websites with **Playwright** (handles JS-heavy pages)  
- Detect **XSS** in URLs and forms  
- Detect **basic SQL Injection** vulnerabilities  
- Check for missing **security headers**:  
  - `Content-Security-Policy`  
  - `X-Frame-Options`  
  - `Strict-Transport-Security`  
- Skip non-HTTP URLs (`javascript:`, `mailto:`, `tel:`)  
- Restrict crawling to the **same domain**  
- Limit crawl depth to prevent infinite loops  
- Single-page UI: results are displayed below the input form  
- Safe handling of exceptions and timeouts  

---

## Requirements

- Python 3.8+  
- Pip packages:

```bash
pip install flask requests bs4 playwright validators
playwright install