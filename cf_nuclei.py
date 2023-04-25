import requests
import json
import subprocess
import os
import sys
import socket
from dotenv import load_dotenv

load_dotenv()

# Read the Cloudflare API token from the .env file
CLOUDFLARE_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")

# API URL and headers
API_BASE_URL = "https://api.cloudflare.com/client/v4/"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
}

def is_host_alive(host, ports=(80, 443), timeout=3):
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                return True
    return False

def prepare_custom_templates():

    print("Checking if custom_templates directory exists...")   

    if not os.path.exists("custom_templates"):
        print("Creating custom_templates directory...")
        os.makedirs("custom_templates")
        print("Cloning Nuclei templates from GitHub...")
        subprocess.run("git clone https://github.com/projectdiscovery/nuclei-templates.git", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Copying high and critical severity templates...")
        
        command = 'find nuclei-templates -type f -name "*.yaml" -exec grep -lE "severity: (high|critical)" {} \; -exec cp {} custom_templates/ \;'
        subprocess.run(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        print("custom_templates directory already exists.")

def get_zone_id(domain_name):
    url = f"{API_BASE_URL}zones?name={domain_name}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        result = response.json()
        if result["result"]:
            return result["result"][0]["id"]
    return None

def get_a_records(zone_id):
    all_records = []
    url = f"{API_BASE_URL}zones/{zone_id}/dns_records?type=A"
    page = 1
    per_page = 100

    while True:
        response = requests.get(f"{url}&page={page}&per_page={per_page}", headers=HEADERS)
        if response.status_code == 200:
            result = response.json()
            a_records = result["result"]
            all_records.extend(a_records)

            # Check if there are more pages
            total_pages = result["result_info"]["total_pages"]
            if page < total_pages:
                page += 1
            else:
                break
        else:
            break

    return all_records if all_records else None


def scan_domain_with_nuclei(domain):
    output_file = f"{domain}_nuclei_output.txt"
    command = f"nuclei -t custom_templates/ -target https://{domain} -o {output_file}"
    process = subprocess.run(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if process.returncode == 0:
        print(f"Scan completed for {domain}. Results saved in {output_file}")
    else:
        print(f"Error scanning {domain} with Nuclei")

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <domain_name>")
        sys.exit(1)

    domain_name = sys.argv[1]
    prepare_custom_templates()

    zone_id = get_zone_id(domain_name)
    if zone_id:
        print(f"Found zone id for {domain_name}")
        print("Getting A records...")
        a_records = get_a_records(zone_id)
        
        if a_records:
            num_records = len(a_records)
            print(f"Found {num_records} A records for {domain_name}")
            
            for record in a_records:
               
                domain = record['name']
                
                if is_host_alive(domain):
                    print(f"{domain} is alive. Scanning with Nuclei...")
                    scan_domain_with_nuclei(domain)
                else:
                    print(f"{domain} is not alive. Skipping Nuclei scan.")
        else:
            print("No A records found.")
    else:
        print("Domain not found in your Cloudflare account.")

if __name__ == "__main__":
    main()
