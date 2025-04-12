# gScan - Advanced Web Technology Scanner 🚀

gScan is an advanced web technology scanner and footprinting tool designed to detect web technologies, discover API endpoints, and assess common vulnerabilities on a target website. This project is developed by **Robot Father**.

## Features ✨

- **Technology Detection:**  
  Detects popular CMS platforms such as WordPress and Joomla, along with modern JavaScript frameworks like React, Angular, and Vue.js.

- **API Discovery:**  
  Scans for API endpoints by checking HTML links and script files for common API patterns.

- **Footprinting:**  
  Gathers detailed server information, DNS records, robots.txt insights, sitemap details, and hidden directories.

- **Vulnerability Scanning:**  
  Performs basic vulnerability checks including SQL Injection, XSS, and directory listing detection.

- **Reporting:**  
  Generates a comprehensive JSON report with scan details, vulnerabilities, and server information.

## Requirements ⚙️

- **Python 3**  
- Required Python packages:  
  - `requests`
  - `beautifulsoup4`
  - `dns.resolver` (from `dnspython`)
  - `pyfiglet`
  - `termcolor`
  - `ipwhois` (for ASN lookup; optional)
  
Install the dependencies using pip:

```bash
pip3 install requests beautifulsoup4 dnspython pyfiglet termcolor ipwhois
```

## Installation 📦

1. **Clone the repository:**

   ```bash
   git clone https://github.com/robot-fprog/gScan.git
   ```

2. **Ensure all dependencies are installed (see the Requirements section).**

## Usage 💻

Run the scanner by providing the target URL:

```bash
python3 gscan.py https://example.com
```

The tool will perform a complete scan including technology detection, footprinting, and vulnerability assessments. After the scan, a JSON report will be saved with details of the scan.

## Security Considerations 🔒

- The tool uses timeouts and error-handling measures to prevent hanging or crashes.
- Commands are executed in a controlled manner (e.g., WPScan integration) to avoid injection risks.
- Ensure you have proper authorization to scan any website before running the tool.

## Contribution 🤝

Contributions are welcome! Feel free to fork the repository and submit pull requests. For any issues or feature requests, please open an issue in the GitHub repository.

## License 📄

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---

Happy scanning! 🚀🔍
