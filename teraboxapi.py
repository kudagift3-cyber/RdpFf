#!/usr/bin/env python3
"""
TeraBox Direct Download API for Termux
Fixed for SSL, DNS, and double-www issues
"""

import os
import re
import time
import requests
import certifi
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('terabox_api.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

class TeraBoxAPI:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 11; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Referer': 'https://www.terabox.com/',
            'Origin': 'https://www.terabox.com'
        })

    def validate_url(self, url):
        patterns = [
            r'(terabox|1024terabox|teraboxapp)\.com\/s\/[a-zA-Z0-9_-]+',
            r'(terabox|1024terabox|teraboxapp)\.app\/s\/[a-zA-Z0-9_-]+',
            r'(terabox|1024terabox|teraboxapp)\.cn\/s\/[a-zA-Z0-9_-]+'
        ]
        return any(re.search(pattern, url) for pattern in patterns)

    def extract_share_key(self, url):
        match = re.search(r'/s/([a-zA-Z0-9_-]+)', url)
        return match.group(1) if match else None

    def format_file_size(self, size_bytes):
        if size_bytes == 0:
            return "0 B"
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        return f"{size_bytes:.2f} {size_names[i]}"

    def get_direct_link(self, share_url):
        """Extract direct download link using certifi for SSL"""
        try:
            if not self.validate_url(share_url):
                raise ValueError("Invalid TeraBox URL format")

            share_key = self.extract_share_key(share_url)
            if not share_key:
                raise ValueError("Cannot extract share key from URL")

            logger.info(f"Processing TeraBox URL: {share_url}")

            # Step 1: Get the share page
            response = self.session.get(share_url, timeout=30, verify=certifi.where())
            response.raise_for_status()

            # Extract domain from final URL
            final_url = response.url
            parsed_url = urlparse(final_url)
            domain = parsed_url.netloc

            # Remove duplicate 'www.'
            if domain.startswith("www."):
                domain = domain[4:]

            # Step 2: Build API endpoint
            api_params = {
                'app_id': '250528',
                'shorturl': share_key,
                'root': '1'
            }
            api_url = f"https://{domain}/share/list"

            # Update referer
            self.session.headers['Referer'] = f"https://{domain}/s/{share_key}"

            # Step 3: Make API request
            api_response = self.session.get(api_url, params=api_params, timeout=30, verify=certifi.where())
            api_response.raise_for_status()

            data = api_response.json()

            if data.get('errno') != 0:
                raise ValueError(f"API Error: {data.get('errmsg', 'Unknown error')}")

            if not data.get('list') or len(data['list']) == 0:
                raise ValueError("No files found in the shared link")

            file_info = data['list'][0]

            if 'dlink' not in file_info:
                raise ValueError("Direct download link not available")

            result = {
                'success': True,
                'data': {
                    'direct_link': file_info['dlink'],
                    'filename': file_info.get('server_filename', 'unknown'),
                    'size': self.format_file_size(file_info.get('size', 0)),
                    'size_bytes': file_info.get('size', 0),
                    'thumbnail': file_info.get('thumbs', {}).get('url3'),
                    'md5': file_info.get('md5'),
                    'category': file_info.get('category'),
                    'original_url': share_url,
                    'processed_at': datetime.now().isoformat()
                }
            }

            logger.info(f"Successfully processed: {file_info.get('server_filename')}")
            return result

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error: {str(e)}")
            return {
                'success': False,
                'error': f'Network error: {str(e)}'
            }
        except Exception as e:
            logger.error(f"Processing error: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

# Rate limiting
rate_limits = {}

def check_rate_limit(ip_address, max_requests=50, time_window=3600):
    current_time = time.time()
    for ip in list(rate_limits.keys()):
        rate_limits[ip] = [t for t in rate_limits[ip] if current_time - t < time_window]
        if not rate_limits[ip]:
            del rate_limits[ip]
    if ip_address not in rate_limits:
        rate_limits[ip_address] = []
    if len(rate_limits[ip_address]) >= max_requests:
        return False
    rate_limits[ip_address].append(current_time)
    return True

# Initialize API
terabox_api = TeraBoxAPI()

@app.route('/api/terabox', methods=['GET', 'POST'])
def process_terabox_url():
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    if not check_rate_limit(client_ip):
        return jsonify({'success': False, 'error': 'Rate limit exceeded. Try again later.'}), 429

    url = request.args.get('url') if request.method == 'GET' else (request.get_json() or {}).get('url')
    if not url:
        return jsonify({'success': False, 'error': 'URL parameter is required'}), 400

    result = terabox_api.get_direct_link(url)
    status_code = 200 if result['success'] else 400
    return jsonify(result), status_code

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat(), 'version': '1.0.0'})

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'name': 'TeraBox Direct Download API',
        'version': '1.0.0',
        'endpoints': {
            'POST /api/terabox': {
                'description': 'Get direct download link from TeraBox URL',
                'body': {'url': 'https://terabox.com/s/example'},
            },
            'GET /api/terabox?url=<url>': 'Same as POST but with URL parameter',
            'GET /health': 'Health check endpoint'
        }
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"""
TeraBox Direct Download API Server
==================================
Server starting on port {port}

Usage:
- POST /api/terabox with JSON: {{"url": "https://terabox.com/s/..."}}
- GET /api/terabox?url=https://terabox.com/s/...
""")
    app.run(host='0.0.0.0', port=port, debug=False)
    #api by sml