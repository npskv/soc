import requests
import json
import subprocess
import os
import sys
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

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <domain_name>")
        sys.exit(1)

    domain_name = sys.argv[1]

    zone_id = get_zone_id(domain_name)
    if zone_id:
        print(f"Found zone id for {domain_name}")
        print("Getting A records...")
        a_records = get_a_records(zone_id)
        
        if a_records:
            num_records = len(a_records)
            print(f"Found {num_records} A records for {domain_name}")

            # Create a list of all A hosts found in the domain
            a_hosts = [record['name'] for record in a_records]

            # Save the list of hosts to a file
            hosts_file = f"hosts-{domain_name}.txt"
            with open(hosts_file, "w") as f:
                f.write("\n".join(a_hosts))
            
            # Run nuclei with the hosts file
            print("Running nuclei...")
            nuclei_cmd = f"nuclei -l {hosts_file} -stats -s high,critical -o {domain_name}-output.txt"
            subprocess.run(nuclei_cmd, shell=True)
        else:
            print("No A records found.")
    else:
        print("Domain not found in your Cloudflare account.")

if __name__ == "__main__":
    main()
