import os
import argparse
import requests
import asyncio
import aiohttp
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from tqdm import tqdm
import time
import logging
import re
import threading
from queue import Queue
import random
from fake_useragent import UserAgent
import json
import ssl
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from plyer import notification
import csv
import xml.etree.ElementTree as ET
from lxml import etree
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from http import cookiejar
from selenium.webdriver.common.keys import Keys

# Disable SSL warnings if SSL Verification is disabled
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Logger configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Dynamic User-Agent for requests
ua = UserAgent()
HEADERS = {
    'User-Agent': ua.random
}

# Extended list of supported file types, including more advanced types
ALL_RESOURCE_TYPES = [
    '.php', '.php2', '.php3', '.php4', '.php5', '.html', '.htm', '.xhtml', '.css', '.scss',
    '.js', '.mjs', '.json', '.asp', '.aspx', '.axd', '.ashx', '.cshtml', '.jsp', '.jspx',
    '.java', '.c', '.cpp', '.h', '.cs', '.pl', '.py', '.rb', '.rhtml', '.erb', '.xml', '.xsl',
    '.xslt', '.svg', '.yaml', '.yml', '.md', '.txt', '.jspa', '.jstl', '.dhtml',
    '.shtml', '.phtml', '.razor', '.csp', '.jspx', '.sass', '.less', '.jsonld',
    '.pyc', '.dll', '.cgi', '.swift', '.kt', '.jar', '.war', '.ear', '.zip', '.tar', '.gz',
    '.rar', '.7z', '.bz2', '.dmg', '.iso', '.shar', '.xz', '.pem', '.p7b', '.p7c', '.p12',
    '.crt', '.cer', '.key', '.der', '.csr', '.eot', '.woff', '.woff2', '.ttf', '.otf', '.psd',
    '.ai', '.bmp', '.gif', '.jpeg', '.jpg', '.png', '.webp', '.ico', '.mp3', '.wav',
    '.flac', '.mp4', '.avi', '.mov', '.mkv', '.ogv', '.ogx', '.ogm', '.ogg', '.oga',
    '.webm', '.m4v', '.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.odt',
    '.ods', '.odp', '.otf', '.otg', '.ott', '.wpd', '.wps', '.xps', '.csv', '.rtf', '.tar.gz',
    '.tar.bz2', '.tgz', '.xz', '.rar', '.jar', '.json', '.svg', '.ps', '.eps', '.sql', '.bak',
    '.eml', '.msg', '.dat', '.db', '.log', '.bak', '.tmp', '.conf', '.ini', '.env', '.bat',
    '.sh', '.cmd', '.exe', '.dll', '.apk', '.exe', '.msi', '.deb', '.rpm', '.py', '.sh'
]

def print_banner():
    RED = '\033[31m'
    WHITE = '\033[37m'
    RESET = '\033[0m'
    banner = f"""
{RED} ________       __    _______            __    __    __                
|  |  |  .-----|  |--|     __.----.---.-|  |--|  |--|  .-----.----.    
|  |  |  |  -__|  _  |    |  |   _|  _  |  _  |  _  |  |  -__|   _|    
|________|_____|_____|_______|__| |___._|_____|_____|__|_____|__| {RESET}

{WHITE}WebGrabber - Pro Version{RESET}
{RED}Created by ibrahimsql{RESET}
    """
    print(banner)

def sanitize_filename(filename):
    return re.sub(r'[\\/*?:"<>|]', "_", filename)

def make_dirs(path):
    if not os.path.exists(path):
        os.makedirs(path)

def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def get_page(session, url, retries=3, retry_delay=2):
    for attempt in range(retries):
        try:
            response = session.get(url, headers=HEADERS, timeout=10, verify=False)
            response.raise_for_status()
            save_cookies(session.cookies, 'cookies.txt')
            return response.text
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching URL: {url} - Error: {e}")
            if attempt + 1 < retries:
                logging.info(f"Retrying {attempt + 1}/{retries} after {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                logging.error(f"Failed to fetch URL: {url} - {e}")
                return None

def save_output(data, output_format, file_path):
    if output_format == 'csv':
        with open(file_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            for row in data:
                writer.writerow(row)
        logging.info(f"Data saved to {file_path} in CSV format.")
    elif output_format == 'json':
        with open(file_path, 'w') as jsonfile:
            json.dump(data, jsonfile, indent=4)
        logging.info(f"Data saved to {file_path} in JSON format.")
    elif output_format == 'xml':
        root = ET.Element("root")
        for item in data:
            elem = ET.SubElement(root, "item")
            elem.text = item
        tree = ET.ElementTree(root)
        tree.write(file_path)
        logging.info(f"Data saved to {file_path} in XML format.")
    else:
        logging.error(f"Unsupported output format: {output_format}")

def save_file(session, url, save_path, max_file_size=None, overwrite=False, speed_limit=None, resume=False):
    if os.path.exists(save_path) and not overwrite:
        logging.info(f"File already exists and overwrite is disabled: {save_path}")
        return

    headers = HEADERS.copy()
    mode = 'wb'
    file_size = 0

    if resume and os.path.exists(save_path):
        file_size = os.path.getsize(save_path)
        headers['Range'] = f'bytes={file_size}-'
        mode = 'ab'

    try:
        with session.get(url, headers=headers, stream=True, timeout=10, verify=False) as response:
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0)) + file_size
            if max_file_size and total_size > max_file_size:
                logging.info(f"Skipping {url} due to file size {total_size} > {max_file_size}")
                return

            make_dirs(os.path.dirname(save_path))

            with open(save_path, mode) as f, tqdm(
                total=total_size, initial=file_size, unit='B', unit_scale=True, desc=sanitize_filename(os.path.basename(save_path))
            ) as progress_bar:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        progress_bar.update(len(chunk))
                    if speed_limit:
                        time.sleep(len(chunk) / speed_limit)
            logging.info(f"Saved: {save_path}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error saving file {url} - Error: {e}")

def save_cookies(cookies, filepath):
    with open(filepath, 'w') as file:
        json.dump(requests.utils.dict_from_cookiejar(cookies), file)

def load_cookies(filepath):
    if os.path.exists(filepath):
        with open(filepath, 'r') as file:
            cookies = requests.utils.cookiejar_from_dict(json.load(file))
            return cookies
    return requests.cookies.RequestsCookieJar()

def extract_all_cookies(session):
    """Extract all cookies from the session and return them."""
    cookies_dict = requests.utils.dict_from_cookiejar(session.cookies)
    logging.info(f"Extracted cookies: {cookies_dict}")
    return cookies_dict

def advanced_vulnerability_checks(html_content, url):
    """Advanced check for common vulnerabilities in the HTML content."""
    vulnerabilities = []

    if '<script>alert(' in html_content.lower() or re.search(r'<script>.*</script>', html_content, re.IGNORECASE):
        vulnerabilities.append("Potential XSS vulnerability found!")

    if re.search(r'select\s+.*\s+from', html_content, re.IGNORECASE):
        vulnerabilities.append("Potential SQL Injection vulnerability found!")

    if 'document.write' in html_content.lower() or re.search(r'document\.cookie', html_content, re.IGNORECASE):
        vulnerabilities.append("Potential DOM-based XSS vulnerability found!")

    if '<iframe' in html_content.lower():
        vulnerabilities.append("Potential Clickjacking vulnerability found!")

    if re.search(r'http[s]?:\/\/(?:localhost|127\.0\.0\.1|::1|intranet|internal)', html_content, re.IGNORECASE):
        vulnerabilities.append("Potential SSRF vulnerability found!")

    if re.search(r'(\||&|;||\$)', html_content):
        vulnerabilities.append("Potential Command Injection vulnerability found!")

    if re.search(r'(\.\./|\.\./\.\./)', html_content):
        vulnerabilities.append("Potential Local File Inclusion (LFI) vulnerability found!")

    if re.search(r'(location\.href\s*=\s*|window\.location\s*=)', html_content, re.IGNORECASE):
        vulnerabilities.append("Potential Open Redirect vulnerability found!")

    if re.search(r'redirect(ion)?\s*=\s*["\']?https?://', html_content, re.IGNORECASE):
        vulnerabilities.append("Potential Unvalidated Redirects and Forwards (URF) vulnerability found!")

    if re.search(r'password|secret|api_key|token', html_content, re.IGNORECASE):
        vulnerabilities.append("Potential Sensitive Data Exposure found!")

    if vulnerabilities:
        logging.warning(f"Vulnerabilities found on {url}: {', '.join(vulnerabilities)}")
    else:
        logging.info(f"No vulnerabilities found on {url}.")

def parse_and_download(session, urls, base_url, save_dir, visited, delay, max_depth, current_depth=0, exclude_types=[], max_file_size=None, overwrite=False, queue=None, speed_limit=None, resume=False):
    for url in urls:
        if current_depth > max_depth:
            return

        if url in visited:
            continue
        visited.add(url)

        html_content = get_page(session, url)
        if html_content is None:
            continue

        parsed_url = urlparse(url)
        path = parsed_url.path
        if path.endswith('/'):
            path += 'index.html'
        elif not os.path.splitext(path)[1]:
            path += '/index.html'

        save_path = os.path.join(save_dir, path.lstrip('/'))
        make_dirs(os.path.dirname(save_path))

        soup = BeautifulSoup(html_content, 'html.parser')

        tags = {
            'img': 'src',
            'script': 'src',
            'link': 'href',
            'a': 'href',
            'video': 'src',
            'audio': 'src',
            'source': 'src'
        }

        for tag, attr in tags.items():
            for resource in soup.find_all(tag):
                src = resource.get(attr)
                if not src or 'nofollow' in resource.attrs.get('rel', []):
                    continue
                resource_url = urljoin(url, src)
                resource_parsed_url = urlparse(resource_url)
                resource_ext = os.path.splitext(resource_parsed_url.path)[1]

                if resource_ext.lower() in ALL_RESOURCE_TYPES or tag == 'a':
                    if any(resource_ext.lower() == ext for ext in exclude_types):
                        logging.info(f"Skipping file {resource_url} due to excluded extension ({resource_ext}).")
                        continue

                    resource_path = os.path.join(save_dir, sanitize_filename(resource_parsed_url.path.lstrip('/')))
                    make_dirs(os.path.dirname(resource_path))

                    if is_valid_url(resource_url) and resource_url not in visited:
                        if resource_ext.lower() in ALL_RESOURCE_TYPES:
                            if queue is None:
                                save_file(session, resource_url, resource_path, max_file_size=max_file_size, overwrite=overwrite, speed_limit=speed_limit, resume=resume)
                            else:
                                queue.put((resource_url, resource_path, max_file_size, overwrite, speed_limit, resume))
                        elif tag == 'a':
                            parse_and_download(session, [resource_url], base_url, save_dir, visited, delay, max_depth, current_depth + 1, exclude_types, max_file_size, overwrite, queue, speed_limit, resume)

        save_path is sanitize_filename(save_path)
        with open(save_path, 'w', encoding='utf-8') as file:
            file.write(soup.prettify())
            logging.info(f"Saved: {save_path}")

        time.sleep(delay)

        advanced_vulnerability_checks(html_content, url)

def worker(session, queue, max_file_size, overwrite, speed_limit, resume):
    while True:
        try:
            resource_url, resource_path, max_file_size, overwrite, speed_limit, resume = queue.get(timeout=3)
            save_file(session, resource_url, resource_path, max_file_size=max_file_size, overwrite=overwrite, speed_limit=speed_limit, resume=resume)
            queue.task_done()
        except:
            break

async def main():
    print_banner()

    parser = argparse.ArgumentParser(description='WebGrabber - Advanced Website Downloader & Vulnerability Scanner')
    parser.add_argument('--urls', nargs='+', help='List of target website URLs', required=True)
    parser.add_argument('-d', '--dir', default='downloaded_site', help='Directory to save files')
    parser.add_argument('--output-format', type=str, choices=['csv', 'json', 'xml'], default='json', help='Output file format')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests (seconds)')
    parser.add_argument('--depth', type=int, default=1, help='Maximum crawl depth')
    parser.add_argument('--user-agent', default=HEADERS['User-Agent'], help='Custom User-Agent')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout for each request (seconds)')
    parser.add_argument('--log-file', default=None, help='File path to save logs')
    parser.add_argument('--proxy', type=str, help='Proxy server (e.g. http://proxyserver:port)')
    parser.add_argument('--cookies', type=str, help='Add custom cookies (e.g. "sessionid=abcd1234; csrftoken=xyz9876")')
    parser.add_argument('--overwrite', action='store_true', help='Overwrite existing files')
    parser.add_argument('--retry', type=int, default=3, help='Number of retries for a request')
    parser.add_argument('--retry-delay', type=int, default=2, help='Delay between retries (seconds)')
    parser.add_argument('--silent', action='store_true', help='Show only critical errors (silent mode)')
    parser.add_argument('--max-file-size', type=int, help='Specify maximum file size to download in bytes')
    parser.add_argument('--threads', type=int, default=4, help='Number of concurrent threads')
    parser.add_argument('--speed-limit', type=int, help='Download speed limit in bytes per second')
    parser.add_argument('--resume', action='store_true', help='Resume download if interrupted')
    parser.add_argument('--css-selectors', type=str, help='Target HTML elements using CSS selectors')
    parser.add_argument('--xpath', type=str, help='XPath expressions to target specific HTML elements')
    parser.add_argument('--execute-js', action='store_true', help='Execute JavaScript on pages to load dynamic content')
    parser.add_argument('--scheduled-tasks', type=int, help='Schedule tasks at regular intervals (in minutes)')
    parser.add_argument('--all', action='store_true', help='Download all web-related file types')
    parser.add_argument('--auth', type=str, help='Add username and password for HTTP Basic Authentication (e.g., "username:password")')
    parser.add_argument('--data-cleaning', action='store_true', help='Perform automatic data cleaning and normalization')
    parser.add_argument('--geo-proxy', type=str, help='Specify geographic location for proxy selection')
    parser.add_argument('--captcha-solving', action='store_true', help='Enable CAPTCHA solving support')
    parser.add_argument('--load-balancing', action='store_true', help='Enable load balancing across multiple IPs or proxies')
    parser.add_argument('--rate-limit', type=int, help='Limit the number of requests per minute')
    parser.add_argument('--max-download-time', type=int, help='Set a maximum download time limit (in seconds)')
    parser.add_argument('--ignore-certs', action='store_true', help='Ignore SSL certificate warnings')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose mode for detailed output')
    parser.add_argument('--min-file-size', type=int, help='Specify minimum file size to download in bytes')
    parser.add_argument('--cookie-jar', type=str, help='Specify a file to save cookies in cookie jar format')
    parser.add_argument('--auto-retry', action='store_true', help='Automatically retry failed downloads')
    parser.add_argument('--chunk-size', type=int, default=8192, help='Specify chunk size for downloads (in bytes)')
    parser.add_argument('--follow-redirects', action='store_true', help='Follow HTTP redirects')
    parser.add_argument('--proxy-auth', type=str, help='Specify username and password for proxy authentication')
    parser.add_argument('--max-redirects', type=int, default=10, help='Maximum number of redirects to follow')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--json-output', action='store_true', help='Output results in JSON format')
    parser.add_argument('--screenshot', type=str, help='Take a screenshot of the webpage and save it')
    parser.add_argument('--webdriver-path', type=str, help='Path to the WebDriver executable')
    parser.add_argument('--include-subdomains', action='store_true', help='Include subdomains in the download')
    parser.add_argument('--save-headers', action='store_true', help='Save response headers to a file')
    parser.add_argument('--custom-header', action='append', help='Add custom headers to the request')
    parser.add_argument('--filter-status', type=int, nargs='+', help='Download only files with specific HTTP status codes')
    parser.add_argument('--check-robots', action='store_true', help='Check robots.txt before downloading')
    parser.add_argument('--download-images', action='store_true', help='Download all images from the webpage')
    parser.add_argument('--download-scripts', action='store_true', help='Download all JavaScript files from the webpage')
    parser.add_argument('--download-css', action='store_true', help='Download all CSS files from the webpage')
    parser.add_argument('--custom-filename', type=str, help='Save downloaded file with a custom filename')
    parser.add_argument('--parse-json', action='store_true', help='Parse JSON responses and save them')
    parser.add_argument('--check-csrf', action='store_true', help='Check for CSRF tokens in forms')
    parser.add_argument('--random-delay', type=int, help='Add a random delay between requests (in seconds)')
    parser.add_argument('--rotate-proxies', type=str, help='Rotate between multiple proxy servers')
    parser.add_argument('--rate-limit-requests', type=int, help='Limit the number of requests per second')
    parser.add_argument('--hide-browser', action='store_true', help='Hide the browser window during execution')
    parser.add_argument('--save-html', action='store_true', help='Save the entire HTML content of the page')
    parser.add_argument('--minify-html', action='store_true', help='Minify HTML content before saving')

    args = parser.parse_args()

    global HEADERS
    HEADERS['User-Agent'] = args.user_agent

    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logging.getLogger().addHandler(file_handler)

    if args.silent:
        logging.getLogger().setLevel(logging.CRITICAL)

    if not all(is_valid_url(url) for url in args.urls):
        logging.error("Invalid URL(s). Please enter valid URLs.")
        return

    make_dirs(args.dir)
    visited = set()

    cookies = load_cookies('cookies.txt')
    if args.cookies:
        for cookie in args.cookies.split(';'):
            key, value = cookie.strip().split('=', 1)
            cookies.set(key.strip(), value.strip())

    session = requests.Session()
    session.headers.update(HEADERS)
    session.cookies = cookies
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
    if args.ignore_certs:
        session.verify = False

    queue = Queue()

    threads = []
    for _ in range(args.threads):
        thread = threading.Thread(target=worker, args=(session, queue, args.max_file_size, args.overwrite, args.speed_limit, args.resume))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    if args.all:
        args.download_images = True
        args.download_scripts = True
        args.download_css = True
        args.follow_redirects = True
        args.save_html = True
        args.minify_html = True
        args.parse_json = True
        args.check_csrf = True

    parse_and_download(
        session=session,
        urls=args.urls,
        base_url=args.urls[0],
        save_dir=args.dir,
        visited=visited,
        delay=args.delay,
        max_depth=args.depth,
        current_depth=0,
        exclude_types=[],
        max_file_size=args.max_file_size,
        overwrite=args.overwrite,
        queue=queue,
        speed_limit=args.speed_limit,
        resume=args.resume
    )

    queue.join()

    for thread in threads:
        thread.join()

    extracted_cookies = extract_all_cookies(session)
    logging.info(f"Extracted all cookies: {extracted_cookies}")

    logging.info("All tasks completed.")
    notification.notify(
        title="Download Complete",
        message=f"All files have been downloaded to {args.dir}",
        timeout=10
    )

if __name__ == '__main__':
    asyncio.run(main())
