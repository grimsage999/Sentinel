import re
import requests
import os
from flask import Blueprint, request, jsonify
from flask_cors import cross_origin

ioc_enrichment_bp = Blueprint('ioc_enrichment', __name__)

# IOC parsing regex patterns
IOC_PATTERNS = {
    'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
    'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
    'hash_md5': r'\b[a-fA-F0-9]{32}\b',
    'hash_sha1': r'\b[a-fA-F0-9]{40}\b',
    'hash_sha256': r'\b[a-fA-F0-9]{64}\b'
}

def parse_iocs(text):
    """Parse IOCs from raw text using regex patterns"""
    iocs = {
        'ips': [],
        'domains': [],
        'urls': [],
        'hashes': []
    }
    
    # Find IPs
    ips = re.findall(IOC_PATTERNS['ip'], text)
    iocs['ips'] = list(set(ips))  # Remove duplicates
    
    # Find URLs
    urls = re.findall(IOC_PATTERNS['url'], text)
    iocs['urls'] = list(set(urls))
    
    # Find domains (excluding those already in URLs)
    domains = re.findall(IOC_PATTERNS['domain'], text)
    # Filter out domains that are part of URLs
    url_domains = []
    for url in urls:
        domain_match = re.search(r'://([^/]+)', url)
        if domain_match:
            url_domains.append(domain_match.group(1))
    
    filtered_domains = [d for d in domains if d not in url_domains and d not in ips]
    iocs['domains'] = list(set(filtered_domains))
    
    # Find hashes
    hashes = []
    for hash_type in ['hash_md5', 'hash_sha1', 'hash_sha256']:
        found_hashes = re.findall(IOC_PATTERNS[hash_type], text)
        hashes.extend(found_hashes)
    iocs['hashes'] = list(set(hashes))
    
    return iocs

def enrich_ip(ip):
    """Enrich IP address using AbuseIPDB (mock implementation)"""
    # In a real implementation, you would use actual API keys
    # For now, return mock data
    return {
        'source': 'AbuseIPDB',
        'reputation': 'Clean' if ip.startswith('192.168') or ip.startswith('10.') else 'Suspicious',
        'abuse_confidence': 15 if ip.startswith('192.168') else 75,
        'country': 'US',
        'usage_type': 'Data Center' if not ip.startswith('192.168') else 'Corporate'
    }

def enrich_domain(domain):
    """Enrich domain using VirusTotal (mock implementation)"""
    return {
        'source': 'VirusTotal',
        'reputation': 'Malicious' if 'suspicious' in domain.lower() or 'phish' in domain.lower() else 'Clean',
        'detection_ratio': '5/89' if 'suspicious' in domain.lower() else '0/89',
        'categories': ['phishing'] if 'phish' in domain.lower() else ['legitimate'],
        'creation_date': '2023-01-15'
    }

def enrich_url(url):
    """Enrich URL using URLScan.io (mock implementation)"""
    return {
        'source': 'URLScan.io',
        'reputation': 'Malicious' if 'malicious' in url.lower() or 'phish' in url.lower() else 'Clean',
        'screenshot_url': 'https://urlscan.io/screenshots/example.png',
        'redirects': 2 if 'redirect' in url.lower() else 0,
        'technologies': ['Apache', 'PHP'] if 'php' in url.lower() else ['nginx', 'JavaScript']
    }

def enrich_hash(hash_value):
    """Enrich file hash using VirusTotal (mock implementation)"""
    return {
        'source': 'VirusTotal',
        'reputation': 'Malicious' if len(hash_value) == 32 else 'Clean',  # Mock: MD5 hashes are malicious
        'detection_ratio': '45/70' if len(hash_value) == 32 else '0/70',
        'file_type': 'PE32 executable' if len(hash_value) == 32 else 'Unknown',
        'first_seen': '2023-12-01'
    }

@ioc_enrichment_bp.route('/parse_iocs', methods=['POST'])
@cross_origin()
def parse_iocs_endpoint():
    """Parse IOCs from raw text"""
    try:
        data = request.get_json()
        if not data or 'text' not in data:
            return jsonify({'error': 'No text provided'}), 400
        
        text = data['text']
        iocs = parse_iocs(text)
        
        return jsonify({
            'success': True,
            'iocs': iocs
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@ioc_enrichment_bp.route('/enrich_ioc', methods=['POST'])
@cross_origin()
def enrich_ioc_endpoint():
    """Enrich a single IOC"""
    try:
        data = request.get_json()
        if not data or 'ioc_type' not in data or 'ioc_value' not in data:
            return jsonify({'error': 'IOC type and value required'}), 400
        
        ioc_type = data['ioc_type']
        ioc_value = data['ioc_value']
        
        enrichment_data = {}
        
        if ioc_type == 'ip':
            enrichment_data = enrich_ip(ioc_value)
        elif ioc_type == 'domain':
            enrichment_data = enrich_domain(ioc_value)
        elif ioc_type == 'url':
            enrichment_data = enrich_url(ioc_value)
        elif ioc_type == 'hash':
            enrichment_data = enrich_hash(ioc_value)
        else:
            return jsonify({'error': 'Unsupported IOC type'}), 400
        
        return jsonify({
            'success': True,
            'ioc_type': ioc_type,
            'ioc_value': ioc_value,
            'enrichment': enrichment_data
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@ioc_enrichment_bp.route('/enrich_batch', methods=['POST'])
@cross_origin()
def enrich_batch_endpoint():
    """Enrich multiple IOCs at once"""
    try:
        data = request.get_json()
        if not data or 'iocs' not in data:
            return jsonify({'error': 'IOCs list required'}), 400
        
        iocs = data['iocs']
        enriched_results = []
        
        for ioc in iocs:
            ioc_type = ioc.get('type')
            ioc_value = ioc.get('value')
            
            if not ioc_type or not ioc_value:
                continue
            
            enrichment_data = {}
            
            if ioc_type == 'ip':
                enrichment_data = enrich_ip(ioc_value)
            elif ioc_type == 'domain':
                enrichment_data = enrich_domain(ioc_value)
            elif ioc_type == 'url':
                enrichment_data = enrich_url(ioc_value)
            elif ioc_type == 'hash':
                enrichment_data = enrich_hash(ioc_value)
            
            enriched_results.append({
                'ioc_type': ioc_type,
                'ioc_value': ioc_value,
                'enrichment': enrichment_data
            })
        
        return jsonify({
            'success': True,
            'results': enriched_results
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

