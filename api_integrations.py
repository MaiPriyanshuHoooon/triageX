"""
API Integrations Module - Production Ready Templates
===================================================
Templates for integrating with threat intelligence platforms
"""

import requests
import json
import time
from typing import Dict, List, Optional


class VirusTotalAPI:
    """
    VirusTotal API Integration

    VirusTotal is a service that analyzes files and URLs for viruses, worms, trojans and other malware.
    Free tier: 4 requests per minute, 500 requests per day
    """

    def __init__(self, api_key: str):
        """
        Initialize VirusTotal API client

        Args:
            api_key: Your VirusTotal API key (get from https://www.virustotal.com/gui/my-apikey)
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self.rate_limit_delay = 15  # seconds between requests (free tier)

    def check_file_hash(self, file_hash: str) -> Dict:
        """
        Check if file hash exists in VirusTotal database

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            Dictionary with detection results
        """
        url = f"{self.base_url}/files/{file_hash}"

        try:
            response = requests.get(url, headers=self.headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']

                return {
                    'found': True,
                    'hash': file_hash,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'total_scanners': sum(stats.values()),
                    'threat_level': '🔴 Critical' if stats.get('malicious', 0) > 5 else
                                   '🟠 Suspicious' if stats.get('malicious', 0) > 0 else '🟢 Clean',
                    'link': f"https://www.virustotal.com/gui/file/{file_hash}",
                    'raw_data': data
                }
            elif response.status_code == 404:
                return {
                    'found': False,
                    'hash': file_hash,
                    'message': 'Hash not found in VirusTotal database'
                }
            else:
                return {
                    'error': True,
                    'status_code': response.status_code,
                    'message': response.text
                }

        except requests.exceptions.RequestException as e:
            return {
                'error': True,
                'message': f"API request failed: {str(e)}"
            }

    def upload_file(self, file_path: str) -> Dict:
        """
        Upload file to VirusTotal for analysis

        Args:
            file_path: Path to file to upload

        Returns:
            Dictionary with upload results
        """
        url = f"{self.base_url}/files"

        try:
            with open(file_path, 'rb') as f:
                files = {'file': (file_path, f)}
                response = requests.post(url, headers=self.headers, files=files, timeout=60)

            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'analysis_id': data['data']['id'],
                    'message': 'File uploaded successfully. Analysis in progress...'
                }
            else:
                return {
                    'error': True,
                    'status_code': response.status_code,
                    'message': response.text
                }

        except Exception as e:
            return {
                'error': True,
                'message': f"Upload failed: {str(e)}"
            }

    def check_ip(self, ip_address: str) -> Dict:
        """
        Check IP address reputation

        Args:
            ip_address: IP address to check

        Returns:
            Dictionary with IP reputation
        """
        url = f"{self.base_url}/ip_addresses/{ip_address}"

        try:
            response = requests.get(url, headers=self.headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']

                return {
                    'ip': ip_address,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'threat_level': '🔴 Malicious' if stats.get('malicious', 0) > 2 else
                                   '🟠 Suspicious' if stats.get('malicious', 0) > 0 else '🟢 Clean',
                    'link': f"https://www.virustotal.com/gui/ip-address/{ip_address}"
                }
            else:
                return {'error': True, 'message': 'IP not found or API error'}

        except Exception as e:
            return {'error': True, 'message': str(e)}


class AlienVaultOTX:
    """
    AlienVault Open Threat Exchange (OTX) API Integration

    OTX is a threat intelligence sharing platform with millions of indicators.
    Free to use with registration.
    """

    def __init__(self, api_key: str):
        """
        Initialize OTX API client

        Args:
            api_key: Your OTX API key (get from https://otx.alienvault.com/api)
        """
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {"X-OTX-API-KEY": self.api_key}

    def check_ip(self, ip_address: str) -> Dict:
        """Check IP address in OTX"""
        url = f"{self.base_url}/indicators/IPv4/{ip_address}/general"

        try:
            response = requests.get(url, headers=self.headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                return {
                    'ip': ip_address,
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'threat_level': '🔴 High' if data.get('pulse_info', {}).get('count', 0) > 5 else
                                   '🟠 Medium' if data.get('pulse_info', {}).get('count', 0) > 0 else '🟢 Low',
                    'link': f"https://otx.alienvault.com/indicator/ip/{ip_address}"
                }
            else:
                return {'error': True, 'message': 'API error'}

        except Exception as e:
            return {'error': True, 'message': str(e)}

    def check_domain(self, domain: str) -> Dict:
        """Check domain reputation in OTX"""
        url = f"{self.base_url}/indicators/domain/{domain}/general"

        try:
            response = requests.get(url, headers=self.headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                return {
                    'domain': domain,
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'threat_level': '🔴 High' if data.get('pulse_info', {}).get('count', 0) > 5 else
                                   '🟠 Medium' if data.get('pulse_info', {}).get('count', 0) > 0 else '🟢 Low'
                }
            else:
                return {'error': True, 'message': 'API error'}

        except Exception as e:
            return {'error': True, 'message': str(e)}

    def check_file_hash(self, file_hash: str) -> Dict:
        """Check file hash in OTX"""
        url = f"{self.base_url}/indicators/file/{file_hash}/general"

        try:
            response = requests.get(url, headers=self.headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                return {
                    'hash': file_hash,
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'threat_level': '🔴 Malicious' if data.get('pulse_info', {}).get('count', 0) > 0 else '🟢 Clean'
                }
            else:
                return {'error': True, 'message': 'API error'}

        except Exception as e:
            return {'error': True, 'message': str(e)}


class HybridAnalysisAPI:
    """
    Hybrid Analysis API Integration

    Hybrid Analysis is a malware analysis service (powered by Falcon Sandbox)
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.hybrid-analysis.com/api/v2"
        self.headers = {
            "api-key": self.api_key,
            "User-Agent": "Falcon Sandbox",
            "Accept": "application/json"
        }

    def check_file_hash(self, file_hash: str) -> Dict:
        """Check file hash in Hybrid Analysis"""
        url = f"{self.base_url}/search/hash"
        data = {"hash": file_hash}

        try:
            response = requests.post(url, headers=self.headers, data=data, timeout=30)

            if response.status_code == 200:
                results = response.json()
                if results:
                    result = results[0]
                    return {
                        'hash': file_hash,
                        'threat_score': result.get('threat_score', 0),
                        'verdict': result.get('verdict', 'unknown'),
                        'threat_level': '🔴 Malicious' if result.get('threat_score', 0) > 70 else
                                       '🟠 Suspicious' if result.get('threat_score', 0) > 30 else '🟢 Clean'
                    }
                else:
                    return {'found': False, 'message': 'Hash not found'}
            else:
                return {'error': True, 'message': 'API error'}

        except Exception as e:
            return {'error': True, 'message': str(e)}


class ThreatIntelligenceAggregator:
    """
    Aggregates results from multiple threat intelligence sources
    """

    def __init__(self, vt_key: Optional[str] = None, otx_key: Optional[str] = None):
        """Initialize with API keys for different services"""
        self.vt = VirusTotalAPI(vt_key) if vt_key else None
        self.otx = AlienVaultOTX(otx_key) if otx_key else None

    def check_hash_all_sources(self, file_hash: str) -> Dict:
        """
        Check file hash across all available threat intelligence sources

        Returns aggregated results
        """
        results = {
            'hash': file_hash,
            'sources': {},
            'overall_threat': '🟢 Clean',
            'threat_score': 0
        }

        # Check VirusTotal
        if self.vt:
            vt_result = self.vt.check_file_hash(file_hash)
            results['sources']['virustotal'] = vt_result
            if vt_result.get('malicious', 0) > 0:
                results['threat_score'] += vt_result['malicious'] * 10

        # Check OTX
        if self.otx:
            time.sleep(1)  # Rate limiting
            otx_result = self.otx.check_file_hash(file_hash)
            results['sources']['otx'] = otx_result
            if otx_result.get('pulse_count', 0) > 0:
                results['threat_score'] += otx_result['pulse_count'] * 5

        # Determine overall threat level
        if results['threat_score'] > 50:
            results['overall_threat'] = '🔴 Critical'
        elif results['threat_score'] > 20:
            results['overall_threat'] = '🟠 High'
        elif results['threat_score'] > 0:
            results['overall_threat'] = '🟡 Medium'

        return results

    def check_ip_all_sources(self, ip_address: str) -> Dict:
        """Check IP across all sources"""
        results = {
            'ip': ip_address,
            'sources': {},
            'overall_threat': '🟢 Clean',
            'threat_score': 0
        }

        if self.vt:
            vt_result = self.vt.check_ip(ip_address)
            results['sources']['virustotal'] = vt_result
            if vt_result.get('malicious', 0) > 0:
                results['threat_score'] += vt_result['malicious'] * 10

        if self.otx:
            time.sleep(1)
            otx_result = self.otx.check_ip(ip_address)
            results['sources']['otx'] = otx_result
            if otx_result.get('pulse_count', 0) > 0:
                results['threat_score'] += otx_result['pulse_count'] * 5

        if results['threat_score'] > 50:
            results['overall_threat'] = '🔴 Critical'
        elif results['threat_score'] > 20:
            results['overall_threat'] = '🟠 High'
        elif results['threat_score'] > 0:
            results['overall_threat'] = '🟡 Medium'

        return results


# Example usage
if __name__ == "__main__":
    print("=" * 70)
    print("THREAT INTELLIGENCE API INTEGRATION - SETUP GUIDE")
    print("=" * 70)
    print()

    print("📝 How to Get API Keys:")
    print("-" * 70)
    print()
    print("1. VirusTotal (Free Tier: 4 req/min, 500 req/day)")
    print("   • Register at: https://www.virustotal.com/gui/join-us")
    print("   • Get API key from: https://www.virustotal.com/gui/my-apikey")
    print()

    print("2. AlienVault OTX (Free)")
    print("   • Register at: https://otx.alienvault.com/api")
    print("   • API key in your settings after registration")
    print()

    print("3. Hybrid Analysis (Free Tier Available)")
    print("   • Register at: https://www.hybrid-analysis.com/signup")
    print("   • Get API key from your profile settings")
    print()

    print("\n💻 Example Usage:")
    print("-" * 70)
    print("""
# Initialize with your API keys
vt = VirusTotalAPI('YOUR_VT_API_KEY_HERE')
otx = AlienVaultOTX('YOUR_OTX_API_KEY_HERE')

# Check file hash
result = vt.check_file_hash('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
print(f"Threat Level: {result['threat_level']}")
print(f"Detections: {result['malicious']}/{result['total_scanners']}")

# Check IP address
ip_result = vt.check_ip('185.220.101.45')
print(f"IP Threat: {ip_result['threat_level']}")

# Use aggregator for comprehensive analysis
aggregator = ThreatIntelligenceAggregator(
    vt_key='YOUR_VT_KEY',
    otx_key='YOUR_OTX_KEY'
)

comprehensive_result = aggregator.check_hash_all_sources('file_hash_here')
print(f"Overall Threat: {comprehensive_result['overall_threat']}")
""")

    print("\n\n🔐 Security Best Practices:")
    print("-" * 70)
    print("   • Store API keys in environment variables, not in code")
    print("   • Use .env files with python-dotenv package")
    print("   • Never commit API keys to version control")
    print("   • Respect rate limits to avoid API suspension")
    print("   • Implement caching to reduce API calls")
    print()

    print("\n📦 Required Packages:")
    print("-" * 70)
    print("   pip install requests python-dotenv")
    print()
