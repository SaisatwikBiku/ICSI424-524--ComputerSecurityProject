"""
Website Scraper for Security Analysis
Main scraping module that extracts data from websites
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json
import os
from datetime import datetime
import re
import ssl
import socket

class scraper:
    def __init__(self, url):
        self.url = url
        self.domain = urlparse(url).netloc
        self.data = {
            'url': url,
            'domain': self.domain,
            'scan_time': datetime.now().isoformat(),
            'headers': {},
            'forms': [],
            'links': [],
            'scripts': [],
            'cookies': [],
            'meta_tags': [],
            'comments': [],
            'emails': [],
            'phone_numbers': [],
            'technologies': [],
            'ssl_info': {},
            'server_info': {}
        }
    
    def scrape(self):
        """Main scraping function"""
        print(f"[+] Starting scan of {self.url}")
        
        try:
            # Send request with common headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(self.url, headers=headers, timeout=10, verify=True)
            
            # Store response headers
            self.data['headers'] = dict(response.headers)
            self.data['status_code'] = response.status_code
            self.data['cookies'] = [{'name': c.name, 'value': c.value, 'domain': c.domain} 
                                    for c in response.cookies]
            
            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract various components
            self._extract_forms(soup)
            self._extract_links(soup)
            self._extract_scripts(soup)
            self._extract_meta_tags(soup)
            self._extract_comments(soup)
            self._extract_emails(response.text)
            self._extract_phone_numbers(response.text)
            self._detect_technologies(response, soup)
            self._get_ssl_info()
            
            print(f"[+] Scan completed successfully")
            return True
            
        except Exception as e:
            print(f"[-] Error during scraping: {str(e)}")
            self.data['error'] = str(e)
            return False
    
    def _extract_forms(self, soup):
        """Extract all forms from the page"""
        forms = soup.find_all('form')
        for form in forms:
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            # Get all input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                form_data['inputs'].append({
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name', ''),
                    'value': input_tag.get('value', '')
                })
            
            self.data['forms'].append(form_data)
    
    def _extract_links(self, soup):
        """Extract all links from the page"""
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            absolute_url = urljoin(self.url, href)
            self.data['links'].append({
                'url': absolute_url,
                'text': link.get_text(strip=True)
            })
    
    def _extract_scripts(self, soup):
        """Extract all script sources"""
        scripts = soup.find_all('script')
        for script in scripts:
            src = script.get('src')
            if src:
                self.data['scripts'].append(urljoin(self.url, src))
            else:
                # Inline script
                self.data['scripts'].append({'inline': True, 'length': len(script.string or '')})
    
    def _extract_meta_tags(self, soup):
        """Extract meta tags"""
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            self.data['meta_tags'].append({
                'name': meta.get('name', meta.get('property', '')),
                'content': meta.get('content', '')
            })
    
    def _extract_comments(self, soup):
        """Extract HTML comments"""
        from bs4 import Comment
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        self.data['comments'] = [str(comment).strip() for comment in comments]
    
    def _extract_emails(self, text):
        """Extract email addresses"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, text)
        self.data['emails'] = list(set(emails))
    
    def _extract_phone_numbers(self, text):
        """Extract phone numbers"""
        phone_pattern = r'\+?1?\s*\(?[0-9]{3}\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}'
        phones = re.findall(phone_pattern, text)
        self.data['phone_numbers'] = list(set(phones))
    
    def _detect_technologies(self, response, soup):
        """Detect technologies used"""
        technologies = []
        
        # Check server header
        if 'Server' in response.headers:
            technologies.append(f"Server: {response.headers['Server']}")
        
        # Check for common frameworks
        if 'X-Powered-By' in response.headers:
            technologies.append(f"Powered by: {response.headers['X-Powered-By']}")
        
        # Check for CMS signatures
        if soup.find('meta', {'name': 'generator'}):
            generator = soup.find('meta', {'name': 'generator'})['content']
            technologies.append(f"CMS: {generator}")
        
        self.data['technologies'] = technologies
    
    def _get_ssl_info(self):
        """Get SSL certificate information"""
        try:
            hostname = urlparse(self.url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    self.data['ssl_info'] = {
                        'version': ssock.version(),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'notAfter': cert['notAfter']
                    }
        except Exception as e:
            self.data['ssl_info'] = {'error': str(e)}
    
    def save_to_file(self, output_dir='scraped_data'):
        """Save scraped data to JSON file"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Create filename from domain and timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.domain}_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        
        print(f"[+] Data saved to {filepath}")
        return filepath


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python web_scraper.py <url>")
        print("Example: python web_scraper.py https://example.com")
        sys.exit(1)
    
    url = sys.argv[1]
    
    # Ensure URL has scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    scraperer = scraper(url)
    if scraperer.scrape():
        scraperer.save_to_file()
    else:
        print("[-] Scraping failed")