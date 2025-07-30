import os
import hashlib
import requests
import magic
import socket
import ssl
from urllib.parse import urlparse
from PIL import Image
import pytesseract
import PyPDF2
import docx
from datetime import datetime
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from tkinter import ttk
import json


def get_ip_geolocation(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return {}


def get_whois_info(domain):
    try:
        response = requests.get(f"https://api.hackertarget.com/whois/?q={domain}", timeout=5)
        if response.status_code == 200:
            return response.text
    except:
        pass
    return "Unavailable"


def scan_file(path):
    result = {}
    if not os.path.exists(path):
        return {"error": "File does not exist."}

    result['File'] = path
    result['Size'] = f"{os.path.getsize(path)/1024:.2f} KB"

    with open(path, 'rb') as f:
        data = f.read()
        result['SHA256'] = hashlib.sha256(data).hexdigest()

    mime = magic.Magic(mime=True)
    filetype = mime.from_file(path)
    result['Type'] = filetype

    if filetype == 'application/pdf':
        with open(path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            meta = reader.metadata
            result['Metadata'] = {k: str(v) for k, v in meta.items() if v}
            content = ""
            for page in reader.pages[:3]:
                content += page.extract_text() or ""
            result['PDF Content Preview'] = content.strip()[:1000]
    elif filetype in ['application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
        doc = docx.Document(path)
        result['Word Content Preview'] = ' '.join([p.text for p in doc.paragraphs if p.text])[:1000]
    elif filetype.startswith('image/'):
        img = Image.open(path)
        text = pytesseract.image_to_string(img)
        result['OCR Text'] = text[:1000]

    return result


def scan_url(url):
    result = {}
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path
        result['Domain'] = hostname

        ip = socket.gethostbyname(hostname)
        result['IP'] = ip

        result['IP Geolocation'] = get_ip_geolocation(ip)
        result['WHOIS Info'] = get_whois_info(hostname)

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                result['SSL Valid Until'] = cert.get('notAfter', 'Unavailable')
                result['SSL Certificate'] = cert

        resp = requests.get(url, timeout=5)
        result['Status Code'] = resp.status_code
        result['Redirects'] = len(resp.history)
        result['Headers'] = dict(resp.headers)

        soup = BeautifulSoup(resp.text, 'html.parser')
        title = soup.title.string.strip() if soup.title else "N/A"
        result['Title'] = title

    except Exception as e:
        result['error'] = f"Failed to scan URL: {str(e)}"

    return result


def display_result_gui(result):
    output.delete('1.0', tk.END)
    if 'error' in result:
        output.insert(tk.END, f"❌ Error: {result['error']}\n")
        return
    for key, value in result.items():
        output.insert(tk.END, f"\n🔹 {key}:\n")
        if isinstance(value, dict):
            for sub_key, sub_val in value.items():
                output.insert(tk.END, f"    ▸ {sub_key}: {sub_val}\n")
        else:
            output.insert(tk.END, f"    {value}\n")


def browse_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        result = scan_file(filepath)
        display_result_gui(result)


def scan_input_url():
    url = url_entry.get()
    if url:
        result = scan_url(url)
        display_result_gui(result)


# GUI Setup
root = tk.Tk()
root.title("🛡️ Milo Advanced Info Scanner")
root.geometry("1000x750")
root.configure(bg="#101820")

style = ttk.Style()
style.theme_use("clam")
style.configure("TButton", padding=6, relief="flat", background="#005a9c", foreground="white")

header = tk.Label(root, text="🔍 Milo Info Scanner", font=("Helvetica", 20, "bold"), bg="#101820", fg="#00d9ff")
header.pack(pady=15)

frame = tk.Frame(root, bg="#101820")
frame.pack(pady=10)

browse_btn = tk.Button(frame, text="📁 Scan File", font=("Helvetica", 12), command=browse_file, bg="#4caf50", fg="white", padx=10)
browse_btn.grid(row=0, column=0, padx=10)

url_entry = tk.Entry(frame, font=("Helvetica", 12), width=50)
url_entry.grid(row=0, column=1, padx=10)

url_btn = tk.Button(frame, text="🌐 Scan URL", font=("Helvetica", 12), command=scan_input_url, bg="#2196f3", fg="white")
url_btn.grid(row=0, column=2, padx=10)

output = scrolledtext.ScrolledText(root, font=("Consolas", 11), wrap=tk.WORD, width=110, height=32, bg="#1c1f26", fg="#e6e6e6", insertbackground="white")
output.pack(pady=20)

footer = tk.Label(root, text="Built with ❤️ by Milo AI", font=("Helvetica", 10), bg="#101820", fg="#888888")
footer.pack(pady=5)

root.mainloop()