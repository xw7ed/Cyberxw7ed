# VulnHunter by xw7ed

**VulnHunter** is an open-source web vulnerability scanner designed to help security professionals and developers identify common vulnerabilities on websites. This tool scans for multiple vulnerabilities like **SQL Injection**, **XSS**, **Open Redirect**, **SSL**, **CSRF**, and also checks for missing HTTP security headers such as **HSTS**, **CSP**, and **X-Frame-Options**. The app also includes a website crawling feature to gather all the links on a webpage for further analysis.

## Features

- **Start Scan**: This feature scans the website for common vulnerabilities such as SQL Injection, XSS, Open Redirect, SSL issues, CSRF, and missing or misconfigured HTTP security headers.
- **Start Crawl**: This feature crawls through all pages of the website and collects all the links available on the site.
- **Save Results**: Allows you to save the results of the scan to a text file for later review.
- **Save Results as CSV**: This option allows you to save the scan results in a CSV format, which is perfect for analysis or reporting.

## Vulnerabilities Scanned

VulnHunter scans for the following vulnerabilities:

1. **SQL Injection (SQLi)**: Tests if the website is vulnerable to SQL injection attacks by injecting common SQL payloads into query parameters.
2. **Cross-Site Scripting (XSS)**: Checks for possible XSS vulnerabilities by injecting script payloads into query parameters.
3. **Open Redirect**: Detects open redirect vulnerabilities where the site redirects users to an external site.
4. **SSL/TLS**: Verifies if the website is using SSL/TLS encryption (HTTPS) and if the SSL certificate is properly configured.
5. **Cross-Site Request Forgery (CSRF)**: Scans for missing or weak CSRF protections on forms.
6. **HTTP Headers**: Ensures important HTTP security headers like **Strict-Transport-Security (HSTS)**, **Content-Security-Policy (CSP)**, and **X-Frame-Options** are configured correctly.

## Requirements

Before running the tool, ensure that you have the following Python libraries installed:

- `requests`: For sending HTTP requests to websites.
- `beautifulsoup4`: For parsing and extracting HTML data during site crawling.
- `Pillow`: For handling and displaying images, including logos.

You can install all the required dependencies with the following command:

```bash
pip install -r requirements.txt

How to Use

    Run the Application:

        Clone the repository and navigate to the project folder.

        Ensure all required dependencies are installed using the command above.

        Run the app using Python:

        python VulnHunter.py

    Enter the URL:

        In the application’s interface, enter the URL of the website you want to scan in the "Enter URL" field.

    Select Scan Type:

        Click Start Scan to begin scanning the website for vulnerabilities.

        Alternatively, click Start Crawl to gather all the links on the website.

    Save the Results:

        After the scan is complete, you can choose to save the results as a text file or a CSV file using the Save Results or Save Results as CSV buttons.

Example

    Enter a website URL (e.g., http://example.com).

    Start the scan by clicking Start Scan.

    Once completed, review the vulnerabilities found in the Results box.

    Save the results to a file for documentation or further analysis.



    Developer: xw7ed

