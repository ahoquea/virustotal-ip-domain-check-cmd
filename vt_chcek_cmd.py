import requests
import sys
import time

# Replace this with your ONLY VirusTotal API key
API_KEY = "VIRUSTOTAL_API_KEY"
HEADERS = {
    "x-apikey": API_KEY
}

def check_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = requests.get(url, headers=HEADERS)
    return parse_response(response, ip)

def check_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    response = requests.get(url, headers=HEADERS)
    return parse_response(response, domain)

def parse_response(response, target):
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        result = f"{target} -> Harmless: {stats['harmless']}, Suspicious: {stats['suspicious']}, Malicious: {stats['malicious']}"
    else:
        result = f"{target} -> Error: {response.status_code} {response.text}"
    return result

def is_ip(target):
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in target.split(".")) and len(target.split(".")) == 4

def main():
    if len(sys.argv) < 2:
        print("Command: python vt_check_cmd.py <ip_or_domain1> <ip_or_domain2> ...")
        return

    targets = sys.argv[1:]
    for target in targets:
        if is_ip(target):
            print(check_ip(target))
        else:
            print(check_domain(target))

if __name__ == "__main__":
    main()
