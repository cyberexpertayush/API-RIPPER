"""
SSL Configuration utility for ARSec
This module provides SSL configuration to suppress SSL certificate verification errors
"""

import ssl
import urllib3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

# Disable urllib3 SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Create a custom SSL context that doesn't verify certificates
class NoVerifyHTTPSAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

def configure_ssl_verification():
    """
    Configure SSL verification to be disabled globally
    This should be called at the start of the application
    """
    # Disable SSL verification at the Python level
    ssl._create_default_https_context = ssl._create_unverified_context
    
    # Also disable SSL verification for urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    print("SSL verification disabled globally")

def get_requests_session():
    """
    Get a requests session with SSL verification disabled
    """
    session = requests.Session()
    session.mount('https://', NoVerifyHTTPSAdapter())
    session.verify = False
    return session
