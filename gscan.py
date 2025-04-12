

"""
gScan - Advanced Web Technology Scanner
Author: Robot Father
GitHub: https://github.com/robot-fprog/gScan
"""

import os
import sys
import requests
import subprocess
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import argparse
import json
import dns.resolver
from datetime import datetime
import concurrent.futures
from pyfiglet import Figlet

from termcolor import colored
import socket

class gScan:
    def __init__(self, target):
        self.target = self.normalize_url(target)
        self.technologies = []
        self.vulnerabilities = []
        self.exposed_files = []
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    @staticmethod
    def normalize_url(url):
        """Ensure URL has proper scheme"""
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url
        return url

    def print_banner(self):
        """Display ASCII art banner"""
        f = Figlet(font='slant')
        banner = colored(f.renderText('gScan'), 'cyan')
        print(banner)
        print(colored("🚀 Advanced Web Technology Scanner & Footprinting Tool", 'yellow'))
        print(colored("🔍 Version: 1.0 | GitHub: https://github.com/yourusername/gScan\n", 'yellow'))

    def detect_tech(self):
        """Detect web technologies with improved checks"""
        print(colored("\n[+] TECHNOLOGY DETECTION PHASE", 'magenta'))
        
        tech_checks = [
            ('WordPress', self.check_wordpress),
            ('Joomla', self.check_joomla),
            ('React', self.check_react),
            ('Angular', self.check_angular),
            ('Vue.js', self.check_vue),
            ('Static', self.check_static),
            ('API Endpoints', self.detect_apis)  
        ]

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            for name, check_func in tech_checks:
                futures.append(executor.submit(check_func))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.technologies.append(result)
                        print(colored(f"  ✅ Found: {result}", 'green'))
                except Exception as e:
                    print(colored(f"  ⚠️ Error in detection: {str(e)}", 'red'))

        if not self.technologies:
            print(colored("  ❌ No major technologies detected", 'red'))
        else:
            print(colored(f"\n  🎯 Identified Technologies: {', '.join(self.technologies)}", 'cyan'))

    def check_wordpress(self):
        """Check for WordPress"""
        try:
            resp = self.session.get(f"{self.target}/wp-login.php", timeout=10)
            if resp.status_code == 200 and 'wp-login.php' in resp.text:
                return 'WordPress'
        except:
            return None

    def check_joomla(self):
        """Check for Joomla"""
        try:
            resp = self.session.get(f"{self.target}/administrator", timeout=10)
            if resp.status_code == 200 and 'joomla' in resp.text.lower():
                return 'Joomla'
        except:
            return None

    def check_react(self):
        """Improved React detection"""
        try:
            resp = self.session.get(self.target, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            react_indicator = any(
                'react-devtools' in script.get('src', '') or
                '__REACT_DEVTOOLS_' in script.text
                for script in soup.find_all('script')
            )
            
            react_attrs = any(
                element.has_attr('data-reactroot') or 
                element.has_attr('data-reactid')
                for element in soup.find_all()
            )
            
            return 'React' if (react_indicator or react_attrs) else None
        except:
            return None

    def check_angular(self):
        """Check for Angular"""
        try:
            resp = self.session.get(self.target, timeout=10)
            if 'ng-app' in resp.text or 'angular' in resp.text.lower():
                return 'Angular'
        except:
            return None
    def check_api_endpoint(self, url):
        """Check if API endpoint is valid"""
        try:
            resp = self.session.get(url, timeout=8)
            content_type = resp.headers.get('Content-Type', '')
            
            # Detect common API response formats
            if resp.status_code < 400 and any(
                ct in content_type for ct in [
                    'json', 'xml', 'graphql', 
                    'text/plain', 'octet-stream'
                ]
            ):
                return True
        except:
            return False
    def check_vue(self):
        """Improved Vue.js detection"""
        try:
            resp = self.session.get(self.target, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Check for Vue.js in script tags
            vue_script = any(
                'vue' in script.get('src', '').lower() or
                'new Vue' in script.text
                for script in soup.find_all('script')
            )
            
            # Check for Vue-specific attributes
            vue_attrs = any(
                element.has_attr('v-bind') or 
                element.has_attr('v-model')
                for element in soup.find_all()
            )
            
            return 'Vue.js' if (vue_script or vue_attrs) else None
        except:
            return None
    def detect_apis(self):
        """API endpoint discovery"""
        print(colored("\n[+] API DISCOVERY PHASE", 'magenta'))
        found_apis = []
        
        try:
            resp = self.session.get(self.target, timeout=15)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            api_patterns = [
                '/api/', '/graphql', '/rest/', 
                '/v1/', '/v2/', '/oauth/'
            ]
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                if any(pattern in href for pattern in api_patterns):
                    found_apis.append(href)
                    print(colored(f"  🔗 Found API endpoint: {href}", 'cyan'))
            
            for script in soup.find_all('script', src=True):
                if script['src'].endswith('.js'):
                    try:
                        js_resp = self.session.get(script['src'], timeout=10)
                        js_content = js_resp.text
                        
                        # Look for fetch/axios calls
                        api_calls = re.findall(
                            r'(?:fetch|axios|ajax)\([\'\"](.*?)[\'\"]\)',
                            js_content
                        )
                        
                        for api in api_calls:
                            if any(pattern in api for pattern in api_patterns):
                                found_apis.append(api)
                                print(colored(f"  🔍 Found API call: {api}", 'blue'))
                    except:
                        continue
            
            # Check common API paths
            common_api_endpoints = [
                '/api', '/graphql', '/rest', 
                '/oauth2', '/auth', '/v1'
            ]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(
                        self.check_api_endpoint, 
                        f"{self.target}{endpoint}"
                    ): endpoint for endpoint in common_api_endpoints
                }
                
                for future in concurrent.futures.as_completed(futures):
                    endpoint = futures[future]
                    try:
                        if future.result():
                            found_apis.append(endpoint)
                            print(colored(f"  🎯 Discovered API: {endpoint}", 'green'))
                    except:
                        pass
            
            return found_apis if found_apis else None
            
        except Exception as e:
            print(colored(f"  ⚠️ API discovery error: {str(e)}", 'red'))
            return None
    def check_static(self):
        """Check for static site"""
        try:
            resp = self.session.get(self.target, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            scripts = soup.find_all('script')
            if len(scripts) < 3 and not any('wp-' in str(s) for s in scripts):
                return 'Static'
        except:
            return None

    def footprint(self):
        """Comprehensive footprinting"""
        print(colored("\n[+] FOOTPRINTING PHASE", 'magenta'))
        self.get_server_info()
        self.get_dns_info()
        self.check_robots()
        self.check_sitemap()
        self.find_hidden_dirs()
        self.find_exposed_files()

    def get_server_info(self):
        """Get server information"""
        print(colored("\n  🌐 Server Information:", 'blue'))
        try:
            resp = self.session.get(self.target, timeout=10)
            server = resp.headers.get('Server', 'Not Found')
            powered = resp.headers.get('X-Powered-By', 'Not Found')
            print(colored(f"    Server: {server}", 'yellow'))
            print(colored(f"    X-Powered-By: {powered}", 'yellow'))
            
            # Get IP and location
            domain = urlparse(self.target).netloc
            ip = socket.gethostbyname(domain)
            print(colored(f"    IP Address: {ip}", 'yellow'))
            
            # Get ASN info (simplified)
            try:
                import ipwhois
                obj = ipwhois.IPWhois(ip)
                results = obj.lookup_rdap()
                asn = results.get('asn', 'Unknown')
                print(colored(f"    ASN: {asn}", 'yellow'))
            except:
                pass
            
        except Exception as e:
            print(colored(f"    ⚠️ Error getting server info: {str(e)}", 'red'))

    def get_dns_info(self):
        """Get DNS records"""
        print(colored("\n  🔍 DNS Information:", 'blue'))
        domain = urlparse(self.target).netloc
        try:
            # A records
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                print(colored(f"    A Record: {rdata.address}", 'yellow'))
            
            # MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                for rdata in answers:
                    print(colored(f"    MX Record: {rdata.exchange} (Priority: {rdata.preference})", 'yellow'))
            except:
                pass
                
            # TXT records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    print(colored(f"    TXT Record: {rdata.strings}", 'yellow'))
            except:
                pass
                
        except Exception as e:
            print(colored(f"    ⚠️ Error in DNS lookup: {str(e)}", 'red'))

    def check_robots(self):
        """Check robots.txt for sensitive info"""
        print(colored("\n  🤖 Robots.txt Analysis:", 'blue'))
        try:
            resp = self.session.get(f"{self.target}/robots.txt", timeout=10)
            if resp.status_code == 200:
                print(colored("    Found robots.txt file:", 'green'))
                disallowed = [line for line in resp.text.split('\n') if line.lower().startswith('disallow:')]
                for item in disallowed[:5]:  # Show first 5 disallowed paths
                    print(colored(f"    {item.strip()}", 'yellow'))
                
                if len(disallowed) > 5:
                    print(colored(f"    ... and {len(disallowed)-5} more disallowed paths", 'yellow'))
            else:
                print(colored("    No robots.txt file found", 'red'))
        except Exception as e:
            print(colored(f"    ⚠️ Error checking robots.txt: {str(e)}", 'red'))

    def check_sitemap(self):
        """Check sitemap.xml"""
        print(colored("\n  🗺️ Sitemap Analysis:", 'blue'))
        try:
            resp = self.session.get(f"{self.target}/sitemap.xml", timeout=10)
            if resp.status_code == 200:
                print(colored("    Found sitemap.xml file", 'green'))
                # Count URLs in sitemap
                url_count = resp.text.count('<url>') or resp.text.count('<urlset')
                print(colored(f"    Contains ~{url_count} URLs", 'yellow'))
            else:
                print(colored("    No sitemap.xml file found", 'red'))
        except Exception as e:
            print(colored(f"    ⚠️ Error checking sitemap.xml: {str(e)}", 'red'))

    def find_hidden_dirs(self):
        """Find hidden directories"""
        print(colored("\n  🔦 Checking Common Hidden Directories:", 'blue'))
        common_dirs = [
            '/admin', '/backup', '/wp-admin', '/administrator',
            '/.git', '/.svn', '/.env', '/config'
        ]
        
        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.check_dir, dir): dir for dir in common_dirs}
            for future in concurrent.futures.as_completed(futures):
                dir = futures[future]
                try:
                    if future.result():
                        found.append(dir)
                        print(colored(f"    Found: {dir}", 'green'))
                except:
                    pass
        
        if not found:
            print(colored("    No common hidden directories found", 'red'))

    def check_dir(self, directory):
        """Check if directory exists"""
        try:
            resp = self.session.get(f"{self.target}{directory}", timeout=5)
            return resp.status_code == 200
        except:
            return False

    def find_exposed_files(self):
        """Find exposed sensitive files"""
        print(colored("\n  📁 Checking for Exposed Files:", 'blue'))
        common_files = [
            '/.env', '/config.php', '/wp-config.php',
            '/phpinfo.php', '/.htaccess', '/web.config'
        ]
        
        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.check_file, file): file for file in common_files}
            for future in concurrent.futures.as_completed(futures):
                file = futures[future]
                try:
                    if future.result():
                        found.append(file)
                        print(colored(f"    Found: {file}", 'green'))
                        self.exposed_files.append(file)
                except:
                    pass
        
        if not found:
            print(colored("    No common exposed files found", 'red'))

    def check_file(self, file_path):
        """Check if file exists"""
        try:
            resp = self.session.get(f"{self.target}{file_path}", timeout=5)
            return resp.status_code == 200 and len(resp.text) > 0
        except:
            return False

    def scan_vulnerabilities(self):
        """Run vulnerability scans based on detected tech"""
        print(colored("\n[+] VULNERABILITY SCANNING PHASE", 'magenta'))
        
        if not self.technologies:
            print(colored("  ⚠️ No technologies detected - running basic scans", 'yellow'))
            self.run_basic_scans()
            return
            
        for tech in self.technologies:
            if tech == 'WordPress':
                self.scan_wordpress()
            elif tech == 'Joomla':
                self.scan_joomla()
            elif tech in ['React', 'Angular', 'Vue.js']:
                self.scan_spa()
            else:
                self.run_basic_scans()

    def scan_wordpress(self):
        """WordPress specific scans"""
        print(colored("\n  🖥️ WordPress Scan:", 'blue'))
        print(colored("    Running WPScan (requires wpscan installed)...", 'yellow'))
        
        try:
            result = subprocess.run(['wpscan', '--url', self.target, '--no-update', '--format', 'cli-no-color'], 
                                  capture_output=True, text=True, timeout=300)
            print(colored(result.stdout, 'yellow'))
        except FileNotFoundError:
            print(colored("    WPScan not installed. Install with: gem install wpscan", 'red'))
        except Exception as e:
            print(colored(f"    Error running WPScan: {str(e)}", 'red'))

    def scan_joomla(self):
        """Joomla specific scans"""
        print(colored("\n  🖥️ Joomla Scan:", 'blue'))
        print(colored("    Checking common Joomla vulnerabilities...", 'yellow'))
        
        # Check for administrator access
        try:
            resp = self.session.get(f"{self.target}/administrator", timeout=10)
            if resp.status_code == 200:
                print(colored("    Administrator panel is accessible", 'red'))
            else:
                print(colored("    Administrator panel not directly accessible", 'green'))
        except Exception as e:
            print(colored(f"    Error checking admin panel: {str(e)}", 'red'))

    def scan_spa(self):
        """SPA framework scans"""
        print(colored("\n  🖥️ SPA Framework Scan:", 'blue'))
        print(colored("    Checking common SPA vulnerabilities...", 'yellow'))
        
        # Check for source map exposure
        try:
            resp = self.session.get(f"{self.target}/static/js/main.js.map", timeout=10)
            if resp.status_code == 200:
                print(colored("    ⚠️ Source map file exposed (main.js.map)", 'red'))
                self.vulnerabilities.append('Exposed source map')
            else:
                print(colored("    No source map file exposed", 'green'))
        except Exception as e:
            print(colored(f"    Error checking source maps: {str(e)}", 'red'))

    def run_basic_scans(self):
        """Run basic vulnerability scans"""
        print(colored("\n  🔍 Running Basic Vulnerability Checks:", 'blue'))
        
        # Check for common vulnerabilities
        checks = [
            ('SQL Injection', self.check_sqli),
            ('XSS', self.check_xss),
            ('Directory Listing', self.check_directory_listing)
        ]
        
        for name, check_func in checks:
            try:
                if check_func():
                    print(colored(f"    ⚠️ Potential {name} vulnerability", 'red'))
                    self.vulnerabilities.append(name)
                else:
                    print(colored(f"    No {name} vulnerability detected", 'green'))
            except Exception as e:
                print(colored(f"    Error checking {name}: {str(e)}", 'red'))

    def check_sqli(self):
        """Check for basic SQLi vulnerability"""
        try:
            test_url = f"{self.target}/product?id=1'"
            resp = self.session.get(test_url, timeout=10)
            return 'sql' in resp.text.lower() or 'syntax' in resp.text.lower()
        except:
            return False

    def check_xss(self):
        """Check for basic XSS vulnerability"""
        try:
            test_url = f"{self.target}/search?q=<script>alert(1)</script>"
            resp = self.session.get(test_url, timeout=10)
            return '<script>alert(1)</script>' in resp.text
        except:
            return False

    def check_directory_listing(self):
        """Check for directory listing"""
        try:
            test_url = f"{self.target}/images/"
            resp = self.session.get(test_url, timeout=10)
            return 'Index of /' in resp.text
        except:
            return False

    def generate_report(self):
        """Generate scan report"""
        print(colored("\n[+] GENERATING REPORT", 'magenta'))
        
        report = {
            'target': self.target,
            'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'technologies': self.technologies,
            'api_endpoints': self.detect_apis() or [],
            'vulnerabilities': self.vulnerabilities,
            'exposed_files': self.exposed_files,
            'server_info': {}
        }
        
        try:
            resp = self.session.get(self.target, timeout=10)
            report['server_info']['server'] = resp.headers.get('Server', 'Not Found')
            report['server_info']['powered_by'] = resp.headers.get('X-Powered-By', 'Not Found')
        except:
            pass
        
        # Save report to JSON file
        filename = f"gscan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        
        print(colored(f"  📝 Report saved to {filename}", 'green'))
        return report

    def run(self):
        """Run complete scan"""
        self.print_banner()
        print(colored(f"🔎 Target: {self.target}\n", 'cyan'))
        
        # Run all phases
        self.detect_tech()
        self.footprint()
        self.scan_vulnerabilities()
        
        # Generate report
        report = self.generate_report()
        
        # Print summary
        print(colored("\n[🎯] SCAN SUMMARY", 'cyan'))
        print(colored(f"  Target: {self.target}", 'yellow'))
        print(colored(f"  Technologies: {', '.join(self.technologies) if self.technologies else 'None detected'}", 'yellow'))
        print(colored(f"  Vulnerabilities Found: {len(self.vulnerabilities)}", 'red' if self.vulnerabilities else 'green'))
        print(colored(f"  Exposed Files: {len(self.exposed_files)}", 'red' if self.exposed_files else 'green'))
        
        print(colored("\n✨ Scan completed! Check the JSON report for full details.", 'cyan'))

def main():
    parser = argparse.ArgumentParser(description='gScan - Advanced Web Technology Scanner')
    parser.add_argument('target', help='URL of the target website')
    parser.add_argument('--output', help='Output file name for the report')
    
    args = parser.parse_args()
    
    scanner = gScan(args.target)
    scanner.run()

if __name__ == '__main__':
    main()

