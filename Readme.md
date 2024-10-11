Genesis: Multi-Vulnerability Scanner


Genesis is a  versatile multi-vulnerability scanner designed to detect various web application vulnerabilities, including Local File Inclusion (LFI), Open Redirects (OR), SQL Injection, Cross-Site Scripting (XSS), Server Side Request Forgery(SSRF), Server Side Template Injection(SSTI), External Entity Injection (XXE). This tool was created by Huey_Lael.

Features

LFI Scanner: Detect Local File Inclusion vulnerabilities
OR Scanner: Identify Open Redirect vulnerabilities
SQL Scanner: Detect SQL Injection vulnerabilities
XSS Scanner: Identify Cross-Site Scripting vulnerabilities
SSRF Scanner: Identify Server Side Request Forgery vulnerabilities
SSTI Scanner : Identify Server Side Template Injection vulnerabilities
XXE Scanner : Identify External Entity Injection vulnerabilities
Os Scanner:  Identify Os Command injection vulnerabilities 
Multi-threaded scanning for improved performance
Customizable payloads and success criteria
User-friendly command-line interface
Option to save vulnerable URLs to a file

Requirements

Python 3.x
Required Python packages (automatically installed):
requests==2.28.1
prompt_toolkit==3.0.36
colorama==0.4.6
aiohttp==3.8.6

Installation

Clone the repository:
git clone https://github.com/Professor-blu/genesis
cd genesis
Run the script:
python genesis.py
The script will automatically check for and install any missing required packages.

Usage
Run the script and select the desired scanning option from the menu.
Follow the prompts to provide the necessary information:
Input file containing URLs or a single URL
Payload file
Success criteria patterns
Number of concurrent threads
The scanner will start and display the results in real-time.
After scanning, you'll have the option to save vulnerable URLs to a file.

Customization

Payload files: Create custom payload files for each vulnerability type.
Success criteria: Adjust the success criteria patterns to fit your specific use case.
Concurrent threads: Modify the number of threads to balance between speed and system resources.

Disclaimer
This tool is for educational and ethical testing purposes only. Always obtain proper authorization before scanning any websites or systems you do not own or have explicit permission to test.

Contributors:

Huey_Lael
