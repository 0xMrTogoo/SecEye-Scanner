import subprocess
import csv
import os
import requests
import time
import ipaddress
import re

# Paths to store the exported Sysmon logs
sysmon_log_file = "C:/Users/asus/Documents/SecEye_Scanner/sysmon_network_logs.csv"
output_file_ips = "C:/Users/asus/Documents/SecEye_Scanner/ips.txt"
malicious_output_file_ips = "C:/Users/asus/Documents/SecEye_Scanner/malicious_ips.txt"
output_file_domains = "C:/Users/asus/Documents/SecEye_Scanner/domains.txt"
malicious_output_file_domains = "C:/Users/asus/Documents/SecEye_Scanner/malicious_domains.txt"

ips = set()
domains = set()

# List of popular domains to filter out
popular_domains = {
    "google", "cloudflare", "microsoft", "zvelo",
    "gravatar", "kali", "amazon", "chatgpt", "bing", "msn",
    "in-addr.arpa", "yahoo", "twitter", "github", "virustotal",
    "wordpress", "azure", "linkedin", "openai", "telegram", 
    "youtube", "whatsapp"
}

# Function to generate trusted IP ranges using ipaddress module
def generate_trusted_ips():
    trusted_ips = set()
    
    ranges = [
        ("8.8.8.0/24"),  # Google DNS
        ("8.8.4.0/24"),  # Google DNS
        ("1.1.1.0/24"),  # Cloudflare DNS
        ("172.217.0.0/16"),  # Google services
        ("104.244.0.0/16"),  # Twitter
        ("199.232.0.0/16"),  # GitHub
        ("13.0.0.0/8"),  # Microsoft Azure
        ("20.0.0.0/8"),
        ("40.76.0.0/14"),
        ("104.208.0.0/16"),
        ("52.0.0.0/8"),  # Amazon AWS
        ("51.0.0.0/8"),
        ("149.154.0.0/16"), # Telegram
        ("69.63.0.0/16"),  # Facebook
        ("192.168.0.0/16") # Private IP
    ]
    
    for ip_range in ranges:
        trusted_ips.add(ipaddress.IPv4Network(ip_range))
    
    return trusted_ips

# Initialize trusted IPs
trusted_ips = generate_trusted_ips()

API_KEYS = [#YOU NEED 11 VIRUSTOTAL API KEYS TO MAKE THE SCRIPT WORK PERFECT,
            #KJCHDSKFHSDJGDJKHKJSFHGFDGHF,
            #KJCHDSKFHSDJGDJKHKJSFHGFDGHF,
            #KJCHDSKFHSDJGDJKHKJSFHGFDGHF,
]

VIRUSTOTAL_DOMAIN_URL = "https://www.virustotal.com/vtapi/v2/domain/report"
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
api_index = 0
request_count = 0  

# ASCII Banner for the tool
def print_banner():
    print(r"""
    ===========================
 _____           _____                 
/  ___|         |  ___|                
\ `--.  ___  ___| |__ _   _  ___       
 `--. \/ _ \/ __|  __| | | |/ _ \      
/\__/ /  __/ (__| |__| |_| |  __/      
\____/ \___|\___\____/\__, |\___|      
 _____      _______    __/ |           
/  ___|   //Aymane//  |___/            
\ `--.  ___ __ _ _ __  _ __   ___ _ __ 
 `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|
/\__/ / (_| (_| | | | | | | |  __/ |   
\____/ \___\__,_|_| |_|_| |_|\___|_|   
                                    
    ===========================
    """)

# Get the next API key in the list

def print_credits():
    credits = """         Tool created by Aymane Bendalaa
    www.linkedin.com/in/aymane-bendalaa-001149241
    https://github.com/aymanebendalaa"""
    print(credits)
def get_next_api_key():
    global api_index, request_count
    api_key = API_KEYS[api_index]
    
    if request_count >= 4:
        api_index = (api_index + 1) % len(API_KEYS)
        request_count = 0
        print(f"\n🔄 Switching to the next API key... 🔑")
        time.sleep(5) 
    
    request_count += 1
    print(f"🌐 Processing with API Key {api_index + 1}/{len(API_KEYS)} | Request {request_count}/4")

    return api_key

def check_ip_reputation(ip):
    api_key = get_next_api_key()
    headers = {
        "x-apikey": api_key
    }
    url = f"{VIRUSTOTAL_IP_URL}{ip}"

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            result, vendors_count, positives, reputation = parse_ip_response(data)
            
            print(f"\n🛡️ IP Address: {ip}")
            print(f"Reputation: {result}")
            print(f"Vendors flagged as malicious: {positives}/{vendors_count}")
            if result == "malicious":
                os.makedirs(os.path.dirname(malicious_output_file_ips), exist_ok=True)
                with open(malicious_output_file_ips, "a") as file:
                    file.write(f"{ip}\nOther INFO => {reputation}\n\n")  # Write the IP to the file, followed by a newline
                
                print(f"Malicious IP {ip} saved to file.")
        else:
            print(f"Error: Unable to fetch data for IP {ip}. Status Code: {response.status_code}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


# Parse the IP response and return whether it's malicious or not (v3)
def parse_ip_response(data):
    positives = 0
    vendors_count = 0
    reputation_info = {}

    if 'data' in data:
        attributes = data['data']['attributes']
        
        # Get the number of malicious flags
        malicious_votes = attributes.get('last_analysis_stats', {}).get('malicious', 0)
        harmless_votes = attributes.get('last_analysis_stats', {}).get('harmless', 0)
        vendors_count = sum(attributes.get('last_analysis_stats', {}).values())

        positives = malicious_votes

        # Get additional reputation information
        reputation_info['country'] = attributes.get('country', 'Unknown')
        reputation_info['as_owner'] = attributes.get('as_owner', 'Unknown')
        # reputation_info['network'] = attributes.get('network', 'Unknown')

        if positives > 0:
            return "malicious", vendors_count, positives, reputation_info
        else:
            return "clean", vendors_count, positives, reputation_info

    return "IP data not found", vendors_count, positives, reputation_info

# Check domain reputation using VirusTotal API
def check_domain_reputation(domain):
    api_key = get_next_api_key()
    params = {"apikey": api_key, "domain": domain}
    response = requests.get(VIRUSTOTAL_DOMAIN_URL, params=params)

    if response.status_code == 200:
        data = response.json()

        malicious = False 

        safety_score = 100 
        if 'Webutation domain info' in data and 'Safety score' in data['Webutation domain info']:
            safety_score = data['Webutation domain info']['Safety score']
            if safety_score < 70:
                malicious = True 

        if 'BitDefender category' in data:
            bitdefender_info = data['BitDefender category']
            if "badware" in bitdefender_info.lower():
                malicious = True  

        if 'Opera domain info' in data:
            opera_info = data['Opera domain info']
            if "badware" in opera_info.lower():
                malicious = True 

        if 'Websense ThreatSeeker category' in data:
            vendor_reliability = data['Websense ThreatSeeker category']
            if vendor_reliability not in ["Excellent", "Good"]:
                malicious = True
        
        if 'Bfore.Ai PreCrime category' in data:
            Bfore_Ai_reliability = data['Bfore.Ai PreCrime category']
            if Bfore_Ai_reliability not in ["Excellent", "Good"]:
                malicious = True
        if 'Bfore.Ai PreCrime category' in data:
            Bfore_Ai_reliability = data['Bfore.Ai PreCrime category']
        # Check if the reliability is neither "Excellent" nor "Good"
            is_reliable = Bfore_Ai_reliability in ["Excellent", "Good"]
            malicious = not is_reliable

        # Assuming 'data' is a dictionary containing your input data
        if 'Bfore.Ai PreCrime category' in data:
            Bfore_Ai_reliability = data['Bfore.Ai PreCrime category']
            
            # Initialize malicious as False
            malicious = False
            
            # Check Bfore.Ai reliability
            if Bfore_Ai_reliability not in ["Excellent", "Good"]:
                malicious = True

        # Now check for the Sophos conditions
        if "Sophos" in data:
            sophos_data = data["Sophos"]
            if sophos_data["category"] == "undetected" and sophos_data["result"] == "unrated":
                malicious = True

        if "Criminal IP" in data:
            Criminal_IP_data = data["Criminal IP"]
            if Criminal_IP_data["category"] == "undetected" and Criminal_IP_data["result"] == "unrated":
                malicious = True

        # After these checks, 'malicious' will be True if either condition is met
        
        if 'Yandex Safebrowsing category' in data:
            Yandex_Safebrowsing_reliability = data['Yandex Safebrowsing category']
            if Yandex_Safebrowsing_reliability not in ["Excellent", "Good"]:
                malicious = True
        return malicious

    else:
        error_message = f"❌ Error {response.status_code}"
        print(error_message)

        
    return False

# Function to run PowerShell command and extract Sysmon logs
def extract_sysmon_logs(event_id):
    powershell_command = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Sysmon/Operational'; Id={event_id}}} | 
    Select-Object TimeCreated, Message |
    Export-Csv -Path "{sysmon_log_file}" -NoTypeInformation
    """
    
    try:
        subprocess.run(["powershell", "-Command", powershell_command], check=True)
        print(f"Successfully extracted Sysmon logs to {sysmon_log_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error extracting Sysmon logs: {e}")


# Function to check if an IP is within the trusted range
def is_ip_trusted(ip):
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        for trusted_ip_range in trusted_ips:
            if ip_obj in trusted_ip_range:
                return True
    except ipaddress.AddressValueError:
        pass
    return False

# Process Sysmon logs for IPs
def process_sysmon_logs_for_ips():
    if os.path.exists(sysmon_log_file):
        print(f"Processing Sysmon logs from {sysmon_log_file}")
        
        with open(sysmon_log_file, newline='') as csvfile:
            log_reader = csv.reader(csvfile)
            next(log_reader)  # Skip header row
            for row in log_reader:
                message = row[1]  # The "Message" field contains the network connection information
                
                if "DestinationIp:" in message:
                    ip = message.split("DestinationIp: ")[1].split()[0]

                    if not is_ip_trusted(ip):
                        ips.add(ip)  # Add the IP address to the set
        
        with open(output_file_ips, 'w') as f_out, open(malicious_output_file_ips, 'w') as mal_out:
            for ip in sorted(ips):
                f_out.write(ip + "\n")
                
                if check_ip_reputation(ip):
                    mal_out.write(ip + "\n")
                    print(f"Malicious IP detected: {ip}")

        print(f"Extracted {len(ips)} unique IPs. Saved to {output_file_ips}")
        print(f"Malicious IPs saved to {malicious_output_file_ips}")

    else:
        print(f"Sysmon log file not found: {sysmon_log_file}")

# Process Sysmon logs for domains
def process_sysmon_logs_for_domains():
    if os.path.exists(sysmon_log_file):
        print(f"Processing Sysmon logs from {sysmon_log_file}")
        
        with open(sysmon_log_file, newline='') as csvfile:
            log_reader = csv.reader(csvfile)
            next(log_reader)  # Skip header row
            for row in log_reader:
                message = row[1]  # The "Message" field contains the DNS query information

                if "QueryName:" in message:
                    domain = message.split("QueryName: ")[1].split()[0]
                    
                    if not any(popular in domain for popular in popular_domains):
                        # Use regex to extract the base domain
                        match = re.search(r'^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$', domain)
                        if match:
                            base_domain = match.group(0)
                            domains.add(base_domain)
        
        with open(output_file_domains, 'w') as f_out, open(malicious_output_file_domains, 'w') as mal_out:
            for domain in sorted(domains):
                f_out.write(domain + "\n")
                
                if check_domain_reputation(domain):
                    mal_out.write(domain + "\n")
                    print(f"Malicious domain detected: {domain}")

        print(f"Extracted {len(domains)} unique domains. Saved to {output_file_domains}")
        print(f"Malicious domains saved to {malicious_output_file_domains}")

    else:
        print(f"Sysmon log file not found: {sysmon_log_file}")

# Main function to link both scripts
def main():
    print_banner()
    print_credits()
    print("\n" + "="*50)
    print("   🚀 Welcome to the My SecEye Scanner Tool! 🚀")
    print("="*50)

    print("\nPlease make a selection:")
    print("1️⃣  Check IP addresses for Network connections")
    print("2️⃣  Check Domain reputations from DNS queries")
    choice = input("\nEnter your choice (1 or 2): ")

    if choice == "1":
        extract_sysmon_logs(3)  # Event ID for Network Connections
        process_sysmon_logs_for_ips()
    elif choice == "2":
        extract_sysmon_logs(22)  # Event ID for DNS Queries
        process_sysmon_logs_for_domains()
    else:
        print("Invalid choice. Exiting...")

if __name__ == "__main__":
    main()
