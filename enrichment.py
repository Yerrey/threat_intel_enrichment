import requests 
import os
import csv


api_key = os.getenv("VT_API_KEY")
ip_list = ["8.8.8.8", "1.1.1.1", "185.220.101.45"]



with open("triage_report.csv", "w", newline='', encoding='utf-8') as file:
    
    writer = csv.writer(file)
    writer.writerow(["IP", "Malicious", "Suspicious", "Harmless", "Verdict"])



    for ip in ip_list:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = requests.get(url, headers ={"x-apikey": api_key})
        result = response.json()


        malicious = result["data"]["attributes"]["last_analysis_stats"]["malicious"]
        suspicious = result["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        harmless = result["data"]["attributes"]["last_analysis_stats"]["harmless"]

        
        print(f"IP: {ip} | Malicious: {malicious} | Suspicious: {suspicious} | Harmless: {harmless}")
        if malicious > 5:
            verdict = "⚠️ HIGH RISK"
            print(verdict)
        elif 1 <= malicious <= 5:
            verdict = "⚠️ SUSPICIOUS"
            print(verdict)
        elif malicious == 0:
            verdict = "✅ CLEAN"
            print(verdict)

        writer.writerow([ip, malicious, suspicious, harmless, verdict])
        

