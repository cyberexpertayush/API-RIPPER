from colorama import Fore
import requests
import re
import time
import json
import os
from urllib.parse import urljoin, urlparse
import warnings

requests.packages.urllib3.disable_warnings()

class SessionManagementScanner:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        self.findings = []
        self.cookies_found = []

        # Common session-related headers and cookies
        self.session_headers = [
            'Set-Cookie', 'X-Session-ID', 'X-Auth-Token',
            'Authorization', 'X-CSRF-Token', 'X-XSRF-Token'
        ]

        # Common session cookie patterns
        self.session_patterns = [
            r'session[_-]?id',
            r'phpsessid',
            r'jsessionid',
            r'asp\.net_sessionid',
            r'auth[_-]?token',
            r'access[_-]?token',
            r'refresh[_-]?token',
            r'csrf[_-]?token'
        ]

    def scan_session_management(self):
        """Main session management scanning function"""
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Scanning session management...{Fore.RESET}", end='', flush=True)

        try:
            # Initial request to get baseline cookies
            initial_response = self.session.get(self.target)
            self.analyze_cookies(initial_response.cookies)
            self.analyze_headers(initial_response.headers)

            # Test various session management aspects
            self.check_session_fixation()
            self.check_session_hijacking()
            self.check_concurrent_sessions()
            self.check_session_timeout()
            self.check_secure_flags()

            # Additional security checks
            self.check_session_prediction()
            self.check_logout_functionality()

            print(f" {Fore.GREEN}Done{Fore.RESET}")

        except Exception as e:
            print(f" {Fore.RED}Error: {str(e)}{Fore.RESET}")

    def analyze_cookies(self, cookies):
        """Analyze cookies for security issues"""
        for cookie in cookies:
            self.cookies_found.append(cookie)

            # Check cookie attributes
            issues = []

            if not cookie.secure:
                issues.append("Missing Secure flag")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append("Missing HttpOnly flag")
            if not cookie.has_nonstandard_attr('SameSite'):
                issues.append("Missing SameSite attribute")
            if cookie.value.isdigit() and len(cookie.value) < 8:
                issues.append("Weak session ID (too short)")
            if re.match(r'^\d+$', cookie.value) and len(set(cookie.value)) < 3:
                issues.append("Predictable session ID pattern")

            if issues:
                self.findings.append({
                    'type': 'Cookie Security Issue',
                    'cookie': cookie.name,
                    'issues': issues,
                    'severity': 'Medium' if len(issues) == 1 else 'High'
                })

    def analyze_headers(self, headers):
        """Analyze headers for session-related security issues"""
        session_headers_found = []
        for header_name, header_value in headers.items():
            if any(pattern.lower() in header_name.lower() for pattern in self.session_headers):
                session_headers_found.append((header_name, header_value))

        if session_headers_found:
            for header_name, header_value in session_headers_found:
                # Check for insecure session headers
                if 'set-cookie' in header_name.lower():
                    if 'secure' not in header_value.lower():
                        self.findings.append({
                            'type': 'Insecure Session Cookie',
                            'header': header_name,
                            'value': header_value[:100],
                            'severity': 'Medium'
                        })

    def check_session_fixation(self):
        """Check for session fixation vulnerabilities"""
        try:
            # Make initial request to get session
            response1 = self.session.get(self.target)
            initial_cookies = response1.cookies

            if not initial_cookies:
                return

            # Try to set a custom session ID
            custom_session = "test_session_fixation_123"
            custom_cookies = requests.cookies.RequestsCookieJar()

            for cookie in initial_cookies:
                if any(pattern.lower() in cookie.name.lower() for pattern in self.session_patterns):
                    custom_cookies.set(cookie.name, custom_session, domain=urlparse(self.target).netloc)

            # Make request with custom session ID
            response2 = self.session.get(self.target, cookies=custom_cookies)

            # Check if our custom session ID was accepted
            accepted = False
            for cookie in response2.cookies:
                if cookie.value == custom_session:
                    accepted = True
                    break

            if accepted:
                self.findings.append({
                    'type': 'Session Fixation Vulnerability',
                    'description': 'Application accepts user-controlled session IDs',
                    'severity': 'High'
                })

        except Exception as e:
            pass

    def check_session_hijacking(self):
        """Check for session hijacking prevention mechanisms"""
        try:
            # Check for IP binding
            response = self.session.get(self.target)
            headers = response.headers

            # Look for IP-based session binding headers
            ip_binding_headers = ['X-Forwarded-For', 'CF-Connecting-IP', 'X-Real-IP']
            has_ip_binding = any(header in headers for header in ip_binding_headers)

            if not has_ip_binding:
                self.findings.append({
                    'type': 'Session Hijacking Risk',
                    'description': 'No IP-based session binding detected',
                    'severity': 'Low'
                })

        except Exception as e:
            pass

    def check_concurrent_sessions(self):
        """Check for concurrent session handling"""
        try:
            # Create multiple session instances
            sessions = []
            for i in range(3):
                new_session = requests.Session()
                new_session.verify = False
                sessions.append(new_session)

            # Make requests with different sessions
            responses = []
            for session in sessions:
                try:
                    response = session.get(self.target)
                    responses.append(response)
                except Exception as e:
                    pass

            # Check if all sessions get different cookies (good practice)
            all_cookies = []
            for response in responses:
                for cookie in response.cookies:
                    if any(pattern.lower() in cookie.name.lower() for pattern in self.session_patterns):
                        all_cookies.append(cookie.value)

            unique_cookies = set(all_cookies)
            if len(unique_cookies) == 1 and len(unique_cookies) > 0:
                self.findings.append({
                    'type': 'Concurrent Session Issue',
                    'description': 'All sessions using same session ID',
                    'severity': 'Medium'
                })

        except Exception as e:
            pass

    def check_session_timeout(self):
        """Check session timeout configuration"""
        try:
            # Make initial request
            response = self.session.get(self.target)

            # Wait and check if session is still valid
            time.sleep(30)

            # Make another request
            response2 = self.session.get(self.target)

            # Check if session cookies are still valid
            session_still_valid = False
            for cookie in self.session.cookies:
                if any(pattern.lower() in cookie.name.lower() for pattern in self.session_patterns):
                    session_still_valid = True
                    break

            if session_still_valid:
                self.findings.append({
                    'type': 'Long Session Timeout',
                    'description': 'Session remains active after 30 seconds',
                    'severity': 'Low'
                })

        except Exception as e:
            pass

    def check_secure_flags(self):
        """Check for secure cookie flags and attributes"""
        if not self.cookies_found:
            return

        for cookie in self.cookies_found:
            issues = []

            # Check Secure flag
            if not cookie.secure:
                issues.append("Missing Secure flag")

            # Check HttpOnly flag
            if not hasattr(cookie, '_rest') or 'httponly' not in str(cookie._rest).lower():
                issues.append("Missing HttpOnly flag")

            # Check SameSite attribute
            if not hasattr(cookie, '_rest') or 'samesite' not in str(cookie._rest).lower():
                issues.append("Missing SameSite attribute")

            if issues:
                self.findings.append({
                    'type': 'Insecure Cookie Flags',
                    'cookie': cookie.name,
                    'issues': issues,
                    'severity': 'Medium'
                })

    def check_session_prediction(self):
        """Check for predictable session IDs"""
        try:
            # Collect multiple session IDs
            session_ids = []
            for i in range(5):
                response = requests.get(self.target, verify=False)
                for cookie in response.cookies:
                    if any(pattern.lower() in cookie.name.lower() for pattern in self.session_patterns):
                        session_ids.append(cookie.value)
                        break

            if len(session_ids) < 2:
                return

            # Check for sequential patterns
            sequential = True
            try:
                int_ids = [int(sid, 16) if all(c in '0123456789abcdefABCDEF' for c in sid) else None for sid in session_ids]
                if None not in int_ids:
                    for i in range(len(int_ids) - 1):
                        if int_ids[i + 1] - int_ids[i] != 1:
                            sequential = False
                            break
                else:
                    sequential = False
            except:
                sequential = False

            if sequential:
                self.findings.append({
                    'type': 'Predictable Session IDs',
                    'description': 'Sequential session ID generation detected',
                    'severity': 'High'
                })

        except Exception as e:
            pass

    def check_logout_functionality(self):
        """Check logout functionality and session cleanup"""
        try:
            # Common logout endpoints
            logout_endpoints = [
                '/logout', '/signout', '/logoff', '/exit',
                '/auth/logout', '/user/logout', '/session/destroy'
            ]

            for endpoint in logout_endpoints:
                logout_url = urljoin(self.target, endpoint)
                try:
                    response = self.session.get(logout_url)
                    if response.status_code in [200, 302, 303]:
                        # Check if session is invalidated after logout
                        post_logout_response = self.session.get(self.target)
                        if post_logout_response.status_code not in [401, 403]:
                            self.findings.append({
                                'type': 'Improper Logout',
                                'description': 'Session not properly invalidated after logout',
                                'endpoint': endpoint,
                                'severity': 'Medium'
                            })
                        break
                except:
                    continue

        except Exception as e:
            pass

    def generate_report(self):
        """Generate a summary report of findings and save to file"""
        # Create output directory if it doesn't exist
        output_dir = os.path.join(os.path.dirname(__file__), '..', 'output')
        os.makedirs(output_dir, exist_ok=True)

        # Generate filename based on target
        target_name = urlparse(self.target).netloc.replace('.', '_')
        report_file = os.path.join(output_dir, f'session_management_{target_name}.txt')

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("SESSION MANAGEMENT SECURITY SCAN REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")

            if not self.findings:
                f.write("✅ No critical session management issues found!\n")
                print(f"{Fore.GREEN}[+] Session management report saved to: {report_file}{Fore.RESET}")
                return

            # Group findings by severity
            severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            for finding in self.findings:
                severity_count[finding['severity']] += 1

            f.write("ISSUES FOUND:\n")
            f.write("-" * 30 + "\n")
            for severity, count in severity_count.items():
                if count > 0:
                    f.write(f"{severity}: {count} issues\n")

            f.write("\nDETAILED FINDINGS:\n")
            f.write("-" * 30 + "\n")
            for i, finding in enumerate(self.findings, 1):
                f.write(f"{i}. [{finding['severity']}] {finding['type']}\n")
                if 'description' in finding:
                    f.write(f"   Description: {finding['description']}\n")
                if 'cookie' in finding:
                    f.write(f"   Cookie: {finding['cookie']}\n")
                if 'endpoint' in finding:
                    f.write(f"   Endpoint: {finding['endpoint']}\n")
                if 'issues' in finding and isinstance(finding['issues'], list):
                    f.write("   Issues:\n")
                    for issue in finding['issues']:
                        f.write(f"   - {issue}\n")
                f.write("\n")

            # Add recommendations
            f.write("\nRECOMMENDATIONS:\n")
            f.write("-" * 30 + "\n")
            if severity_count['High'] > 0 or severity_count['Critical'] > 0:
                f.write("🚨 HIGH PRIORITY:\n")
                f.write("- Address all High and Critical severity issues immediately\n")
                f.write("- These vulnerabilities can lead to session hijacking or fixation attacks\n\n")

            if severity_count['Medium'] > 0:
                f.write("⚠️  MEDIUM PRIORITY:\n")
                f.write("- Implement secure cookie flags (Secure, HttpOnly, SameSite)\n")
                f.write("- Ensure proper session timeout configuration\n")
                f.write("- Fix concurrent session handling issues\n\n")

            if severity_count['Low'] > 0:
                f.write("ℹ️  LOW PRIORITY:\n")
                f.write("- Consider implementing IP-based session binding\n")
                f.write("- Add explicit session timeout headers\n")
                f.write("- Implement proper logout functionality\n")

        print(f"{Fore.GREEN}[+] Session management report saved to: {report_file}{Fore.RESET}")
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Found {len(self.findings)} issues ({severity_count['High']} High, {severity_count['Medium']} Medium, {severity_count['Low']} Low){Fore.RESET}")

def session_management_scan(target):
    """Main function to run session management security scan"""
    scanner = SessionManagementScanner(target)
    scanner.scan_session_management()
    scanner.generate_report()
    return scanner.findings
