import streamlit as st
import whois
import socket
import requests
from datetime import datetime
import pandas as pd
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def check_blacklists(domain):
    # Get API key from environment variable
    API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    url = f"https://www.virustotal.com/vtapi/v2/url/report"
    params = {
        'apikey': API_KEY,
        'resource': domain
    }
    try:
        response = requests.get(url, params=params)
        result = response.json()
        return result.get('positives', 0), result.get('total', 0)
    except:
        return "Error", "Error"

def get_domain_info(domain):
    try:
        # Get WHOIS information
        w = whois.whois(domain)
        
        # Get IP address
        ip = socket.gethostbyname(domain)
        
        # Get IP location using ip-api
        ip_info = requests.get(f"http://ip-api.com/json/{ip}").json()
        
        # Check blacklists
        blacklist_detections, total_scanners = check_blacklists(domain)
        
        return {
            "Domain": domain,
            "IP Address": ip,
            "Registration Date": w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date,
            "Location": f"{ip_info.get('city', 'N/A')}, {ip_info.get('country', 'N/A')}",
            "Registrar": w.registrar,
            "Blacklist Status": f"{blacklist_detections}/{total_scanners} detections" if isinstance(blacklist_detections, int) else "API Error"
        }
    except Exception as e:
        return {
            "Domain": domain,
            "IP Address": "Error",
            "Registration Date": "Error",
            "Location": "Error",
            "Registrar": "Error",
            "Blacklist Status": "Error"
        }

# Streamlit UI
st.set_page_config(page_title="SandboxA", page_icon="🔍")
st.title("SandboxA - Domain Analysis Tool")

# Input field for domain
domain_input = st.text_area("Enter domain URLs (one per line)", height=100)

if st.button("Analyze"):
    if domain_input:
        domains = domain_input.split('\n')
        domains = [d.strip() for d in domains if d.strip()]
        
        results = []
        progress_bar = st.progress(0)
        
        for i, domain in enumerate(domains):
            result = get_domain_info(domain)
            results.append(result)
            progress_bar.progress((i + 1) / len(domains))
        
        # Display results in a table
        df = pd.DataFrame(results)
        st.dataframe(df)
        
        # Download button for results
        csv = df.to_csv(index=False)
        st.download_button(
            label="Download Results as CSV",
            data=csv,
            file_name="domain_analysis.csv",
            mime="text/csv"
        )
    else:
        st.warning("Please enter at least one domain URL")

# Footer
st.markdown("---")
st.markdown("Made with ❤️ by Amit Mishra")
