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
from fpdf import FPDF

class WebVulnScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VulnHunter by xw7ed")
        self.root.geometry("700x600")
        self.vulns = []

        try:
            image = Image.open("logo.png").resize((300, 150))
            self.logo = ImageTk.PhotoImage(image)
            logo_label = tk.Label(root, image=self.logo)
            logo_label.pack(pady=5)
        except Exception as e:
            print(f"Error loading logo: {e}")

        self.url_entry = ttk.Entry(root, width=50, font=("Arial", 14))
        self.url_entry.pack(pady=10)

        self.scan_button = ttk.Button(root, text="Start Scan", command=self.start_scan_thread)
        self.scan_button.pack(pady=5)

        self.crawl_button = ttk.Button(root, text="Start Crawl", command=self.start_crawl)
        self.crawl_button.pack(pady=5)

        self.progress = ttk.Progressbar(root, length=200, mode='indeterminate')
        self.progress.pack(pady=5)

        self.result_box = tk.Text(root, height=15, width=80, font=("Arial", 12), wrap="word")
        self.result_box.pack(pady=10)

        self.save_button = ttk.Button(root, text="Save Results", command=self.save_results)
        self.save_button.pack(pady=5)

        self.save_pdf_button = ttk.Button(root, text="Save Results as PDF", command=self.save_results_pdf)
        self.save_pdf_button.pack(pady=5)

        self.save_csv_button = ttk.Button(root, text="Save Results as CSV", command=self.save_results_csv)
        self.save_csv_button.pack(pady=5)

    def start_scan_thread(self):
        thread = threading.Thread(target=self.start_scan)
        thread.start()

    def start_scan(self):
        self.progress.start()
        url = self.url_entry.get()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a website URL")
            self.progress.stop()
            return
        if not url.startswith("http"):
            url = "http://" + url
        self.result_box.delete("1.0", tk.END)
        self.vulns.clear()

        self.vulns.extend(self.check_sql_injection(url))
        self.vulns.extend(self.check_xss(url))
        self.vulns.extend(self.check_http_headers(url))
        self.vulns.extend(self.check_open_redirect(url))
        self.vulns.extend(self.check_ssl(url))
        self.vulns.extend(self.check_csrf(url))
        self.vulns.extend(self.check_lfi(url))

        if self.vulns:
            count = len(self.vulns)
            self.result_box.insert(tk.END, f"{count} Vulnerabilities Found:\n")
            for vuln in self.vulns:
                if "vulnerability" in vuln.lower():
                    self.result_box.insert(tk.END, vuln + "\n", "red")
                else:
                    self.result_box.insert(tk.END, vuln + "\n", "green")
        else:
            self.result_box.insert(tk.END, "No vulnerabilities found.")
        self.progress.stop()

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
                print(f"SQLi error: {e}")
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
                print(f"XSS error: {e}")
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
            print(f"Header check error: {e}")
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
                print(f"Redirect error: {e}")
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
            if '<input type="hidden" name="csrf" value="' not in res.text:
                results.append(f"CSRF vulnerability detected at {url}")
        except Exception as e:
            print(f"CSRF error: {e}")
        return results

    def check_lfi(self, url):
        payloads = ["../../etc/passwd", "../../../etc/passwd", "/etc/passwd"]
        results = []
        for payload in payloads:
            test_url = f"{url}/page?file={payload}"
            try:
                res = requests.get(test_url)
                if "root" in res.text.lower():
                    results.append(f"Possible LFI vulnerability at {test_url}")
            except Exception as e:
                print(f"LFI error: {e}")
        return results

    def start_crawl(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL")
            return
        links = self.crawl_site(url)
        if links:
            self.result_box.insert(tk.END, f"\nFound {len(links)} links:\n")
            self.result_box.insert(tk.END, "\n".join(links))
        else:
            self.result_box.insert(tk.END, "No links found.")

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
            print(f"Crawl error: {e}")
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

    def save_results_csv(self):
        if not self.vulns:
            messagebox.showinfo("Nothing to save", "No results to save.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            with open(file_path, "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["Vulnerability", "URL"])
                for vuln in self.vulns:
                    writer.writerow([vuln])  # Replace with actual URL if needed
            messagebox.showinfo("Saved", f"Results saved to {file_path}")

    def save_results_pdf(self):
        if not self.vulns:
            messagebox.showinfo("Nothing to save", "No results to save.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if file_path:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            pdf.cell(200, 10, txt="Vulnerability Scan Results", ln=True, align="C")
            pdf.ln(10)
            for vuln in self.vulns:
                pdf.multi_cell(0, 10, vuln)
            pdf.output(file_path)
            messagebox.showinfo("Saved", f"Results saved to {file_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = WebVulnScannerApp(root)
    root.mainloop()
