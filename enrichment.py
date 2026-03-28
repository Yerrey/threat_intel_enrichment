import requests 
import os
import csv
import time 


#This PS comand is what creates a temporary environment variable, I am leaving this here so I don't have to keep re typing the whole thing 
#$env:VT_API_KEY = "API_KEY_GOES_HERE"


# the api_key uses os.getenv() to create a temporary variable that lives in the terminal
api_key = os.getenv("VT_API_KEY")
# Defensive check for missing API key 
if api_key is  None:
    print("ERROR: NO API KEY FOUND")
    exit()

indicators = [
    {"type": "ip", "value": "8.8.8.8"},
    {"type": "domain", "value": "google.com"},
    {"type": "ip", "value":"1.1.1.1" },
    {"type": "ip", "value": "185.220.101.45"},
    {"type": "domain", "value": "youtube.com"},
    {"type": "domain", "value": "guitarcenter.com"}
]

def build_url(indicator):
    if indicator["type"] == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator['value']}"
    elif indicator["type"] == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{indicator['value']}"

    return url

def query_virustotal(url, api_key):
    response = requests.get(url, headers = {"x-apikey": api_key})
    result = response.json()
    return result

def get_verdict(malicious):
    if malicious > 5:
        return "⚠️ HIGH RISK"
    if 1 <= malicious <= 5:
        return "⚠️ SUSPICIOUS" 
    if malicious == 0:
        return "✅ CLEAN"
        

def run_analysis(indicators):

    with open("triage_report.csv", "w", newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["IP | DOMAIN", "Malicious", "Suspicious", "Harmless", "Verdict"])

        for indicator in indicators: 
            url = build_url(indicator)
            result = query_virustotal(url,api_key)

            malicious = result["data"]["attributes"]["last_analysis_stats"]["malicious"]
            suspicious = result["data"]["attributes"]["last_analysis_stats"]["suspicious"]
            harmless = result["data"]["attributes"]["last_analysis_stats"]["harmless"]

            verdict = get_verdict(malicious)
            
            print(f"IP/DOMAIN: {indicator['value']} | Malicious: {malicious} | Suspicious: {suspicious} | Harmless: {harmless}")
            print(verdict)
            writer.writerow([indicator["value"], malicious, suspicious, harmless, verdict])
            # using rate limits to stay within VirusTotal's 4 requests per minute
            time.sleep(15)

run_analysis(indicators)




            

