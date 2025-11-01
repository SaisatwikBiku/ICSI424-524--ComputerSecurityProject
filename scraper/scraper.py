import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json
import datetime
import os
import shutil

def scrape_website(url):
    print(f"\n[+] Scanning: {url}\n{'='*50}")
    data = {
        "url": url,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "html_title": "",
        "meta_tags": [],
        "headers": {},
        "links": [],
        "forms": [],
        "scripts": [],
        "cookies": [],
        "server_info": {},
        "status_code": None,
        "technologies": {},
        "notes": []
    }

    try:
        # --- Send GET request ---
        response = requests.get(url, timeout=10)
        data["status_code"] = response.status_code
        data["headers"] = dict(response.headers)
        data["cookies"] = [dict(c) for c in response.cookies]

        # --- Parse HTML ---
        soup = BeautifulSoup(response.text, "html.parser")

        # Page title
        if soup.title:
            data["html_title"] = soup.title.string.strip()

        # Meta tags
        for meta in soup.find_all("meta"):
            data["meta_tags"].append(meta.attrs)

        # Extract all links (absolute URLs)
        for link in soup.find_all("a", href=True):
            full_link = urljoin(url, link['href'])
            data["links"].append(full_link)

        # Extract forms
        for form in soup.find_all("form"):
            form_info = {
                "action": form.get("action"),
                "method": form.get("method", "GET").upper(),
                "inputs": []
            }
            for inp in form.find_all("input"):
                form_info["inputs"].append({
                    "name": inp.get("name"),
                    "type": inp.get("type", "text")
                })
            data["forms"].append(form_info)

        # Extract scripts and CSS files
        for script in soup.find_all("script", src=True):
            full_script = urljoin(url, script['src'])
            data["scripts"].append(full_script)

        for css in soup.find_all("link", rel="stylesheet"):
            full_css = urljoin(url, css['href'])
            data["scripts"].append(full_css)

        # --- Technology Fingerprinting ---
        server = response.headers.get("Server", "")
        powered_by = response.headers.get("X-Powered-By", "")
        if server:
            data["technologies"]["Server"] = server
        if powered_by:
            data["technologies"]["X-Powered-By"] = powered_by

        # --- Security Header Checks ---
        required_headers = [
            "Content-Security-Policy", "Strict-Transport-Security",
            "X-Frame-Options", "X-XSS-Protection", "X-Content-Type-Options"
        ]
        missing_headers = [h for h in required_headers if h not in response.headers]
        if missing_headers:
            data["notes"].append(f"Missing security headers: {', '.join(missing_headers)}")

        # --- HTTP/HTTPS check ---
        if not url.startswith("https"):
            data["notes"].append("Website uses HTTP instead of HTTPS — insecure connection.")

    except requests.exceptions.RequestException as e:
        data["notes"].append(f"Request failed: {str(e)}")

    # --- Save data to file ---
    filename = sanitize_filename(urlparse(url).netloc) + "_data.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
        # change 'scraped_data' to the folder you want inside the repo
        target_folder = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scraped_data"))
        os.makedirs(target_folder, exist_ok=True)

        new_filepath = os.path.join(target_folder, filename)
        try:
            # Ensure the JSON ends up only in the scraped_data folder.
            src = os.path.abspath(filename)
            dst = os.path.abspath(new_filepath)
            if src != dst:
                try:
                    shutil.move(src, dst)
                except Exception:
                    # Fallback for cross-device moves: copy then remove the source.
                    shutil.copy2(src, dst)
                    if os.path.exists(src):
                        os.remove(src)
            filename = dst
        except Exception as e:
            data.setdefault("notes", []).append(f"Could not move file to {target_folder}: {e}")
    print(f"\n✅ Data saved to: {filename}\n")
    return data


def sanitize_filename(name):
    # Clean invalid filename characters
    return "".join(c for c in name if c.isalnum() or c in (' ', '.', '_')).rstrip()


if __name__ == "__main__":
    target_url = input("Enter website URL (e.g., https://example.com): ").strip()
    scrape_website(target_url)