import requests
import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
import ssl
import socket
from bs4 import BeautifulSoup
from PIL import Image, ImageTk
import threading
import csv

class WebVulnScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VulnHunter by xw7ed")
        self.root.geometry("800x700")
        self.vulns = []
        self.active_scans = {}

        style = ttk.Style()
        style.configure("TButton", font=("Arial", 12))
        style.configure("TCheckbutton", font=("Arial", 11))
        style.configure("TLabel", font=("Arial", 12))

        try:
            image = Image.open("logo.png").resize((300, 150))
            self.logo = ImageTk.PhotoImage(image)
            logo_label = tk.Label(root, image=self.logo)
            logo_label.pack(pady=5)
        except Exception as e:
            print(f"Error loading logo: {e}")

        self.url_entry = ttk.Entry(root, width=60, font=("Arial", 13))
        self.url_entry.pack(pady=10)

        checks_frame = ttk.Frame(root)
        checks_frame.pack(pady=5)

        self.scan_options = {
            "SQL Injection": tk.BooleanVar(value=True),
            "XSS": tk.BooleanVar(value=True),
            "Headers": tk.BooleanVar(value=True),
            "Open Redirect": tk.BooleanVar(value=True),
            "SSL": tk.BooleanVar(value=True),
            "CSRF": tk.BooleanVar(value=True)
        }

        for i, (label, var) in enumerate(self.scan_options.items()):
            ttk.Checkbutton(checks_frame, text=label, variable=var).grid(row=0, column=i, padx=5)

        buttons_frame = ttk.Frame(root)
        buttons_frame.pack(pady=5)

        ttk.Button(buttons_frame, text="Start Scan", command=self.start_scan_thread).grid(row=0, column=0, padx=5)
        ttk.Button(buttons_frame, text="Start Crawl", command=self.start_crawl).grid(row=0, column=1, padx=5)
        ttk.Button(buttons_frame, text="Save TXT", command=self.save_results).grid(row=0, column=2, padx=5)
        ttk.Button(buttons_frame, text="Save CSV", command=self.save_results_csv).grid(row=0, column=3, padx=5)

        self.progress = ttk.Progressbar(root, length=200, mode='indeterminate')
        self.progress.pack(pady=5)

        self.result_box = tk.Text(root, height=15, width=90, font=("Consolas", 11), wrap="word")
        self.result_box.pack(pady=10)
        self.result_box.tag_config("success", foreground="green")
        self.result_box.tag_config("warning", foreground="red")
        self.result_box.tag_config("vuln", foreground="orange")
        self.result_box.tag_config("info", foreground="blue")

        ttk.Label(root, text="Activity Log").pack()
        self.log_box = tk.Text(root, height=5, width=90, font=("Consolas", 10), bg="#f9f9f9")
        self.log_box.pack(pady=5)

    def log(self, msg):
        self.log_box.insert(tk.END, f"{msg}\n")
        self.log_box.see(tk.END)

    def start_scan_thread(self):
        thread = threading.Thread(target=self.start_scan)
        thread.start()

    def start_scan(self):
        self.progress.start()
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a website URL")
            self.progress.stop()
            return
        if not url.startswith("http"):
            url = "http://" + url

        self.result_box.delete("1.0", tk.END)
        self.vulns.clear()

        self.result_box.insert(tk.END, f"Scanning {url}...\n", "info")
        self.log(f"[+] Starting scan on {url}")

        if self.scan_options["SQL Injection"].get():
            self.vulns.extend(self.check_sql_injection(url))
        if self.scan_options["XSS"].get():
            self.vulns.extend(self.check_xss(url))
        if self.scan_options["Headers"].get():
            self.vulns.extend(self.check_http_headers(url))
        if self.scan_options["Open Redirect"].get():
            self.vulns.extend(self.check_open_redirect(url))
        if self.scan_options["SSL"].get():
            self.vulns.extend(self.check_ssl(url))
        if self.scan_options["CSRF"].get():
            self.vulns.extend(self.check_csrf(url))

        if self.vulns:
            self.result_box.insert(tk.END, f"\nFound {len(self.vulns)} vulnerabilities:\n", "warning")
            for vuln in self.vulns:
                self.result_box.insert(tk.END, f"• {vuln}\n", "vuln")
        else:
            self.result_box.insert(tk.END, "No vulnerabilities found.", "success")

        self.progress.stop()
        self.log(f"[+] Scan complete. Found {len(self.vulns)} issues.")

    def check_sql_injection(self, url):
        payloads = ["' OR 1=1 --", "' OR 'a'='a", "' AND 1=1 --"]
        results = []
        for payload in payloads:
            test_url = f"{url}/search?q={payload}"
            try:
                res = requests.get(test_url)
                if "database" in res.text.lower():
                    results.append(f"Possible SQL Injection at {test_url}")
            except Exception as e:
                self.log(f"SQLi error: {e}")
        return results

    def check_xss(self, url):
        payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
        results = []
        for payload in payloads:
            test_url = f"{url}/search?q={payload}"
            try:
                res = requests.get(test_url)
                if payload in res.text:
                    results.append(f"Possible XSS at {test_url}")
            except Exception as e:
                self.log(f"XSS error: {e}")
        return results

    def check_http_headers(self, url):
        results = []
        try:
            res = requests.get(url)
            headers = res.headers
            if "Strict-Transport-Security" not in headers:
                results.append(f"HSTS header missing at {url}")
            if "Content-Security-Policy" not in headers:
                results.append(f"CSP header missing at {url}")
            if "X-Frame-Options" not in headers:
                results.append(f"X-Frame-Options header missing at {url}")
        except Exception as e:
            self.log(f"Header check error: {e}")
        return results

    def check_open_redirect(self, url):
        payloads = ["http://evil.com", "https://malicious-site.com"]
        results = []
        for payload in payloads:
            test_url = f"{url}/redirect?to={payload}"
            try:
                res = requests.get(test_url, allow_redirects=False)
                if res.status_code in [301, 302] and "Location" in res.headers:
                    if payload in res.headers["Location"]:
                        results.append(f"Open Redirect possible at {test_url}")
            except Exception as e:
                self.log(f"Redirect error: {e}")
        return results

    def check_ssl(self, url):
        results = []
        if not url.startswith("https://"):
            results.append(f"{url} does not use HTTPS.")
        else:
            try:
                hostname = url.split("://")[1].split("/")[0]
                context = ssl.create_default_context()
                with context.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                    s.settimeout(3)
                    s.connect((hostname, 443))
                    cert = s.getpeercert()
                    if not cert:
                        results.append(f"No SSL certificate found on {url}")
            except Exception as e:
                results.append(f"SSL error on {url}: {str(e)}")
        return results

    def check_csrf(self, url):
        results = []
        try:
            res = requests.get(url)
            if '<input type="hidden" name="csrf"' not in res.text.lower():
                results.append(f"CSRF vulnerability detected at {url}")
        except Exception as e:
            self.log(f"CSRF error: {e}")
        return results

    def start_crawl(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL")
            return
        links = self.crawl_site(url)
        if links:
            self.result_box.insert(tk.END, f"\nFound {len(links)} links:\n", "info")
            self.result_box.insert(tk.END, "\n".join(links) + "\n")
        else:
            self.result_box.insert(tk.END, "No links found.")
        self.log(f"[+] Crawled {len(links)} links from {url}")

    def crawl_site(self, url):
        links = []
        try:
            res = requests.get(url)
            soup = BeautifulSoup(res.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a['href']
                if href.startswith("http"):
                    links.append(href)
        except Exception as e:
            self.log(f"Crawl error: {e}")
        return links

    def save_results(self):
        if not self.vulns:
            messagebox.showinfo("Nothing to save", "No results to save.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                file.write("\n".join(self.vulns))
            messagebox.showinfo("Saved", f"Results saved to {file_path}")
            self.log(f"[+] Results saved to TXT: {file_path}")

    def save_results_csv(self):
        if not self.vulns:
            messagebox.showinfo("Nothing to save", "No results to save.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            with open(file_path, "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["Vulnerability Type", "Message"])
                for vuln in self.vulns:
                    if "SQL Injection" in vuln:
                        vuln_type = "SQL Injection"
                    elif "XSS" in vuln:
                        vuln_type = "Cross-Site Scripting"
                    elif "CSRF" in vuln:
                        vuln_type = "CSRF"
                    elif "Redirect" in vuln:
                        vuln_type = "Open Redirect"
                    elif "SSL" in vuln or "HTTPS" in vuln:
                        vuln_type = "SSL"
                    elif "header" in vuln.lower():
                        vuln_type = "Header"
                    else:
                        vuln_type = "Other"
                    writer.writerow([vuln_type, vuln])
            messagebox.showinfo("Saved", f"Results saved to {file_path}")
            self.log(f"[+] Results saved to CSV: {file_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = WebVulnScannerApp(root)
    root.mainloop()
