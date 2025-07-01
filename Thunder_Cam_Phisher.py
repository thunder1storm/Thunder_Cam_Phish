#!/usr/bin/env python3
import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from fpdf import FPDF

BANNER = r"""
 _______ _                        _                                   
'   /    /      ,   . , __     ___/   ___  .___                       
    |    |,---. |   | |'  `.  /   | .'   ` /   \                      
    |    |'   ` |   | |    | ,'   | |----' |   '                      
    /    /    | `._/| /    | `___,' `.___, /                          
                                  `                                   
  ___                        .___  _               _                  
.'   \   ___  , _ , _        /   \ /      `   ____ /        ___  .___ 
|       /   ` |' `|' `.      |,_-' |,---. |  (     |,---. .'   ` /   \
|      |    | |   |   |      |     |'   ` |  `--.  |'   ` |----' |   '
 `.__, `.__/| /   '   /      /     /    | / \___.' /    | `.___, /    
"""

DEFAULT_HEADERS = {
    "User-Agent": "ThunderWebCheckerAI/1.0 (+https://github.com/thunder1storm/Thunder-Web-Checker)"
}

report_json = []
report_lock = threading.Lock()

def add_result(title, risk_level, summary):
    with report_lock:
        report_json.append({
            "title": title,
            "risk_level": risk_level,
            "summary": summary
        })

def print_banner():
    print(BANNER)

def generate_report_json(filename="thunder_web_checker_report.json"):
    try:
        with open(filename, "w") as f:
            json.dump(report_json, f, indent=4)
        print(f"[+] JSON report saved: {filename}")
    except Exception as e:
        print(f"[-] Failed to save JSON report: {e}")

def generate_report_pdf(filename="thunder_web_checker_report.pdf"):
    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Thunder Web Checker Report", ln=True, align="C")
        pdf.ln(10)
        pdf.set_font("Arial", "B", 12)
        for item in report_json:
            pdf.cell(0, 10, f"Title: {item['title']}", ln=True)
            pdf.set_font("Arial", "", 11)
            pdf.multi_cell(0, 8, f"Risk Level: {item['risk_level'].capitalize()}")
            pdf.multi_cell(0, 8, f"Summary: {item['summary']}")
            pdf.ln(5)
            pdf.set_font("Arial", "B", 12)
        pdf.output(filename)
        print(f"[+] PDF report saved: {filename}")
    except Exception as e:
        print(f"[-] Failed to save PDF report: {e}")

def perform_basic_checks(target):
    print("[+] Performing Basic Target Checks...")
    add_result("Banner", "info", "Thunder Cam Phisher AI Enhanced Scanner")
    add_result("Target Parsed", "info", f"Target URL: {target}")
    try:
        parsed = urlparse(target)
        ip = socket.gethostbyname(parsed.netloc)
        add_result("Target IP Resolved", "low", f"Resolved IP: {ip}")
    except Exception as e:
        add_result("Target IP Resolution Failed", "medium", str(e))

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Thunder Cam Phisher AI - Enhanced Web Security Scanner")
    parser.add_argument("target", help="Target URL or domain to scan (e.g. https://example.com)")
    parser.add_argument("--json-only", action="store_true", help="Only output JSON report")
    parser.add_argument("--pdf-only", action="store_true", help="Only output PDF report")
    args = parser.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = "http://" + target

    perform_basic_checks(target)

    if not args.pdf_only:
        generate_report_json()
    if not args.json_only:
        generate_report_pdf()

if __name__ == "__main__":
    main()
