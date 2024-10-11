class Color:
    BLUE = '\033[94m'
    GREEN = '\033[1;92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    ORANGE = '\033[38;5;208m'
    BOLD = '\033[1m'
    UNBOLD = '\033[22m'
    ITALIC = '\033[3m'
    UNITALIC = '\033[23m'

try:
    import os
    import sys
    import subprocess
    from colorama import Fore, Style, init
    from time import sleep
    from rich import print as rich_print
    from rich.panel import Panel
    from rich.table import Table
    from rich.console import Console
    import concurrent.futures
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urlsplit, urlunsplit, quote
    from bs4 import BeautifulSoup
    import time
    import requests
    import urllib3
    import urllib
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import PathCompleter
    import random
    import argparse
    import aiohttp
    from aiohttp import ClientTimeout
    import asyncio
    import logging
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import yaml
    import string
    from requests.adapters import HTTPAdapter
    from retry import retry
    from functools import lru_cache 
    import json
    from queue import Queue
    from logging.handlers import QueueHandler
    import importlib.metadata as metadata 
    from urllib3.util import Retry
    import socket
    import csv
    from requests.exceptions import RequestException, Timeout
    from aiohttp import ClientSession
    import hashlib
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from curses import panel
    import random
    import re

    init(autoreset=True)

    def check_and_install_packages(packages):
        for package, version in packages.items():
            try:
                __import__(package)
            except ImportError:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', f"{package}=={version}"])

    def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')



    def display_menu():
        title = """
        ██████╗ ███████╗███╗   ██╗███████╗███████╗██╗███████╗
        ██╔════╝ ██╔════╝████╗  ██║██╔════╝██╔════╝██║██╔════╝
        ██║  ███╗█████╗  ██╔██╗ ██║███████╗███████╗██║███████╗
        ██║   ██║██╔══╝  ██║╚██╗██║╚════██║╚════██║██║╚════██║
        ╚██████╔╝███████╗██║ ╚████║███████║███████║██║███████║
        ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝╚══════╝
        """
        print(Color.BLUE + Style.BRIGHT + title.center(63))
        print(Fore.WHITE + Style.BRIGHT + "─" * 63)
        border_color = Color.CYAN + Style.BRIGHT
        option_color = Fore.WHITE + Style.BRIGHT  
        
        print(border_color + "┌" + "─" * 61 + "┐")
        
        options = [
            "1] LFI Scanner",
            "2] OR Scanner",
            "3] SQL Scanner",
            "4] XSS Scanner",
            "5] SSRF Scanner",
            "6] SSTI Scanner",
            "7] XXE scanner",
            "8] OS Scanner",
            "9] Exit"
        ]
        
        for option in options:
            print(border_color + "│" + option_color + option.ljust(59) + border_color + "│")
        
        print(border_color + "└" + "─" * 61 + "┘")
        authors = "Created by: Huey_Lael"
        instructions = "Select an option by entering the corresponding number:"
        
        print(Fore.WHITE + Style.BRIGHT + "─" * 63)
        print(Fore.WHITE + Style.BRIGHT + authors.center(63))
        print(Fore.WHITE + Style.BRIGHT + "─" * 63)
        print(Fore.WHITE + Style.BRIGHT + instructions.center(63))
        print(Fore.WHITE + Style.BRIGHT + "─" * 63)

    def print_exit_menu():
        clear_screen()

        panel = Panel(
            """
        ____            _                 _     
        / ___|  ___  ___| |__   ___  _ __  (_)___ 
        \___ \ / _ \/ __| '_ \ / _ \| '_ \ | / __|
        ___) |  __/ (__| | | | (_) | | | || \__ \\
        |____/ \___|\___|_| |_|\___/|_| |_|/ |___/
                                        |__/         
   
   Credits - Huey_Lael
            """,
            style="bold green",
            border_style="blue",
            expand=False
        )
        rich_print(panel)
        print(Color.RED + "\n\nSession Off ...\n")
        exit()

    def run_sql_scanner():
        try:

            init(autoreset=True)

            def load_user_agents():
                try:
                    with open('config.yaml', 'r') as file:
                        data = yaml.safe_load(file)
                        return data.get('user_agents', [])
                except FileNotFoundError:
                    print(f"{Fore.RED}[!] 'config.yaml' not found.")
                    return []

            def get_random_user_agent():
                user_agents = load_user_agents()
                if user_agents:
                    return random.choice(user_agents)
                else:
                    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            
            def check_and_install_packages(packages):
                for package, version in packages.items():
                    try:
                        __import__(package)
                    except ImportError:
                        subprocess.check_call([sys.executable, '-m', 'pip', 'install', f"{package}=={version}"])

            def clear_screen():
                os.system('cls' if os.name == 'nt' else 'clear')

            
            def prompt_for_http_methods():
                methods = ['GET', 'POST', 'PUT', 'DELETE']
                selected_methods = []

                print(f"{Fore.CYAN}[?] Select HTTP methods for scanning (separated by commas):")
                print(f"{Fore.YELLOW}[i] Available options: {', '.join(methods)}")
                
                user_input = input(f"{Fore.CYAN}[?] Enter your choices (e.g., GET,POST): ").strip().upper()
                
                if not user_input:
                    selected_methods = ['GET'] 
                else:
                    selected_methods = [method.strip() for method in user_input.split(',') if method.strip() in methods]

                if not selected_methods:
                    print(f"{Fore.RED}[!] Invalid HTTP method selected. Defaulting to 'GET'.")
                    selected_methods = ['GET']

                return selected_methods
            
            def perform_request(url, payload, cookie, method, data=None, headers=None):
                url_with_payload = f"{url}{payload}" if method == 'GET' else url
                start_time = time.time()

                if headers is None:
                    headers = {
                        'User-Agent': get_random_user_agent()
                    }
                    
                if not cookie:
                    cookie = generate_random_cookie_value()
                
                try:
                    if method == 'GET':
                        response = requests.get(url_with_payload, headers=headers, cookies={'cookie': cookie} if cookie else None)
                    elif method == 'POST':
                        response = requests.post(url, data=data or payload, headers=headers, cookies={'cookie': cookie} if cookie else None)
                    elif method == 'PUT':
                        response = requests.put(url, data=data or payload, headers=headers, cookies={'cookie': cookie} if cookie else None)
                    elif method == 'DELETE':
                        response = requests.delete(url, headers=headers, cookies={'cookie': cookie} if cookie else None)
                    else:
                        raise ValueError(f"Unsupported HTTP method: {method}")
                    
                    response.raise_for_status()
                    success = True
                    error_message = None
                    analyze_responses(requests.get(url), response, payload)

                except requests.exceptions.RequestException as e:
                    success = False
                    error_message = str(e)

                response_time = time.time() - start_time
                return success, url_with_payload, response_time, error_message
            
            def analyze_responses(baseline_response, test_response, payload):
                """
                Analyzes baseline and test response hashes to detect injection attempts.
                """
                baseline_hash = hash_response_content(baseline_response.text)
                test_hash = hash_response_content(test_response.text)

                if baseline_hash != test_hash:
                    log_vulnerability(test_response.url, payload, test_response.elapsed.total_seconds())
                else:
                    print(f"{Fore.YELLOW}False positive detected with payload: {payload}")
                    
            def log_vulnerability(url, payload, response_time):
                """
                Logs and prints detected vulnerability.
                """
                logging.info(f"Vulnerability found! URL: {url} - Payload: {payload} - Response Time: {response_time:.2f} seconds")
                print(f"{Fore.GREEN}Vulnerable: {url} - Payload: {payload} - Response Time: {response_time:.2f} seconds")

            def log_report(vulnerable_urls):
                """
                Generate a detailed report of vulnerabilities found.
                """
                with open('vulnerability_report.txt', 'w') as report_file:
                    report_file.write(f"Vulnerability Report - {time.ctime()}\n")
                    report_file.write(f"Total vulnerabilities found: {len(vulnerable_urls)}\n\n")
                    for url, payload, response_time in vulnerable_urls:
                        report_file.write(f"Vulnerable URL: {url}\n")
                        report_file.write(f"Payload: {payload}\n")
                        report_file.write(f"Response Time: {response_time:.2f} seconds\n\n")

                print(f"{Fore.CYAN}Vulnerability report generated: vulnerability_report.txt")

            def hash_response_content(content):
                """
                Create a hash of the response content for comparison.
                """
                return hashlib.sha256(content.encode('utf-8')).hexdigest()

            def generate_random_cookie_value(length=10):
                """
                Generate a random cookie for the request if not provided.
                """
                return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

            def get_file_path(prompt_text):
                completer = PathCompleter()
                return prompt(prompt_text, completer=completer).strip()

            def handle_exception(exc_type, exc_value, exc_traceback):
                if issubclass(exc_type, KeyboardInterrupt):
                    print(f"\n{Fore.YELLOW}Program terminated by the user!")
                    save_prompt()
                    sys.exit(0)
                else:
                    print(f"\n{Fore.RED}An unexpected error occurred: {exc_value}")
                    sys.exit(1)

            def save_prompt(vulnerable_urls=[]):
                save_choice = input(f"{Fore.CYAN}\n[?] Do you want to save the vulnerable URLs to a file? (y/n, press Enter for n): ").strip().lower()
                if save_choice == 'y':
                    output_file = input(f"{Fore.CYAN}[?] Enter the name of the output file (press Enter for 'vulnerable_urls.txt'): ").strip() or 'vulnerable_urls.txt'
                    with open(output_file, 'w') as f:
                        for url in vulnerable_urls:
                            f.write(url + '\n')
                    print(f"{Fore.GREEN}Vulnerable URLs have been saved to {output_file}")
                    os._exit(0)
                else:
                    print(f"{Fore.YELLOW}Vulnerable URLs will not be saved.")
                    os._exit(0)

            def prompt_for_urls():
                while True:
                    try:
                        url_input = get_file_path("[?] Enter the path to the input file containing the URLs (or press Enter to input a single URL): ")
                        if url_input:
                            if not os.path.isfile(url_input):
                                raise FileNotFoundError(f"File not found: {url_input}")
                            with open(url_input) as file:
                                urls = [line.strip() for line in file if line.strip()]
                            return urls
                        else:
                            single_url = input(f"{Fore.CYAN}[?] Enter a single URL to scan: ").strip()
                            if single_url:
                                return [single_url]
                            else:
                                print(f"{Fore.RED}[!] You must provide either a file with URLs or a single URL.")
                                input(f"{Fore.YELLOW}\n[i] Press Enter to try again...")
                                clear_screen()
                                print(f"{Fore.GREEN}Welcome to the Genesis SQL-Injector!\n")
                    except Exception as e:
                        print(f"{Fore.RED}[!] Error reading input file: {url_input}. Exception: {str(e)}")
                        input(f"{Fore.YELLOW}[i] Press Enter to try again...")
                        clear_screen()
                        print(f"{Fore.GREEN}Welcome to the Genesis SQL-Injector!\n")

            def prompt_for_payloads():
                while True:
                    try:
                        payload_input = get_file_path("[?] Enter the path to the payloads file: ")
                        if not os.path.isfile(payload_input):
                            raise FileNotFoundError(f"File not found: {payload_input}")
                        with open(payload_input) as file:
                            payloads = [line.strip() for line in file if line.strip()]
                        return payloads
                    except Exception as e:
                        print(f"{Fore.RED}[!] Error reading payload file: {payload_input}. Exception: {str(e)}")
                        input(f"{Fore.YELLOW}[i] Press Enter to try again...")
                        clear_screen()
                        print(f"{Fore.GREEN}Welcome to the Genesis SQL-Injector!\n")

            def print_scan_summary(total_found, total_scanned, start_time):
                print(f"{Fore.YELLOW}\n[i] Scanning finished.")
                print(f"{Fore.YELLOW}[i] Total found: {total_found}")
                print(f"{Fore.YELLOW}[i] Total scanned: {total_scanned}")
                print(f"{Fore.YELLOW}[i] Time taken: {int(time.time() - start_time)} seconds")

            def main():
                clear_screen()
                required_packages = {
                    'requests': '2.28.1',
                    'prompt_toolkit': '3.0.36',
                    'colorama': '0.4.6'
                }

                check_and_install_packages(required_packages)

                time.sleep(3)
                clear_screen()

                panel = Panel(
            """                                                       
               ___                                         
   _________ _/ (_)  ______________ _____  ____  ___  _____
  / ___/ __ `/ / /  / ___/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 (__  ) /_/ / / /  (__  ) /__/ /_/ / / / / / / /  __/ /    
/____/\__, /_/_/  /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
        /_/                                                

                """,
                style="bold green",
                border_style="blue",
                expand=False
                )
                rich_print(panel, "\n")

                print(Fore.GREEN + "Welcome to the SQL Testing Tool!\n")

                urls = prompt_for_urls()
                payloads = prompt_for_payloads()
            
                cookie = input("[?] Enter the cookie to include in the GET request (press Enter if none): ").strip() or None
                methods = prompt_for_http_methods()

                threads = int(input("[?] Enter the number of concurrent threads (0-10, press Enter for 5): ").strip() or 5)
                print(f"\n{Fore.YELLOW}[i] Loading, Please Wait...")
                time.sleep(3)
                clear_screen()
                print(f"{Fore.CYAN}[i] Starting scan...")

                vulnerable_urls = []
                first_vulnerability_prompt = True

                single_url_scan = len(urls) == 1
                start_time = time.time()
                total_scanned = 0
                log_report(vulnerable_urls)

                try:
                    futures = []
                    if threads == 0:
                        for url in urls:
                            for method in methods:  
                                for payload in payloads:
                                    total_scanned += 1
                                    futures.append(executor.submit(perform_request, url, payload, cookie, method))

                        for future in concurrent.futures.as_completed(futures):
                            success, url_with_payload, response_time, error_message = future.result()

                            if response_time >= 10:
                                stripped_payload = url_with_payload.replace(url, '')
                                encoded_stripped_payload = quote(stripped_payload, safe='')
                                encoded_url = f"{url}{encoded_stripped_payload}"
                                if single_url_scan:
                                    print(f"{Fore.YELLOW}\n[i] Scanning with payload: {stripped_payload}")
                                    encoded_url_with_payload = encoded_url
                                else:
                                    list_stripped_payload = url_with_payload
                                    for url in urls:
                                        list_stripped_payload = list_stripped_payload.replace(url, '')
                                    encoded_stripped_payload = quote(list_stripped_payload, safe='')

                                    encoded_url_with_payload = url_with_payload.replace(list_stripped_payload, encoded_stripped_payload)

                                    print(f"{Fore.YELLOW}\n[i] Scanning with payload: {list_stripped_payload}")
                                print(f"{Fore.GREEN}Vulnerable: {Fore.WHITE}{encoded_url_with_payload}{Fore.CYAN} - Response Time: {response_time:.2f} seconds")
                                vulnerable_urls.append(url_with_payload)
                                if single_url_scan and first_vulnerability_prompt:
                                    continue_scan = input(f"{Fore.CYAN}\n[?] Vulnerability found. Do you want to continue testing other payloads? (y/n, press Enter for n): ").strip().lower()
                                    if continue_scan != 'y':
                                        end_time = time.time()
                                        time_taken = end_time - start_time
                                        print(f"{Fore.YELLOW}\n[i] Scanning finished.")
                                        print(f"{Fore.YELLOW}[i] Total found: {len(vulnerable_urls)}")
                                        print(f"{Fore.YELLOW}[i] Total scanned: {total_scanned}")
                                        print(f"{Fore.YELLOW}[i] Time taken: {time_taken:.2f} seconds")

                                        save_prompt(vulnerable_urls)
                                        return
                                    first_vulnerability_prompt = False
                            else:
                                stripped_payload = url_with_payload.replace(url, '')
                                encoded_stripped_payload = quote(stripped_payload, safe='')
                                encoded_url = f"{url}{encoded_stripped_payload}"
                                if single_url_scan:
                                    print(f"{Fore.YELLOW}\n[i] Scanning with payload: {stripped_payload}")
                                    encoded_url_with_payload = encoded_url
                                else:
                                    list_stripped_payload = url_with_payload
                                    for url in urls:
                                        list_stripped_payload = list_stripped_payload.replace(url, '')
                                    encoded_stripped_payload = quote(list_stripped_payload, safe='')

                                    encoded_url_with_payload = url_with_payload.replace(list_stripped_payload, encoded_stripped_payload)

                                    print(f"{Fore.YELLOW}\n[i] Scanning with payload: {list_stripped_payload}")
                                print(f"{Fore.RED}Not Vulnerable: {Fore.WHITE}{encoded_url_with_payload}{Fore.CYAN} - Response Time: {response_time:.2f} seconds")
                    else:
                        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                            for url in urls:
                                for method in methods:  
                                    for payload in payloads:
                                        total_scanned += 1
                                        futures.append(executor.submit(perform_request, url, payload, cookie, method))

                            for future in concurrent.futures.as_completed(futures):
                                success, url_with_payload, response_time, error_message = future.result()

                                if response_time >= 10:
                                    stripped_payload = url_with_payload.replace(url, '')
                                    encoded_stripped_payload = quote(stripped_payload, safe='')
                                    encoded_url = f"{url}{encoded_stripped_payload}"
                                    if single_url_scan:
                                        print(f"{Fore.YELLOW}\n[i] Scanning with payload: {stripped_payload}")
                                        encoded_url_with_payload = encoded_url
                                    else:
                                        list_stripped_payload = url_with_payload
                                        for url in urls:
                                            list_stripped_payload = list_stripped_payload.replace(url, '')
                                        encoded_stripped_payload = quote(list_stripped_payload, safe='')

                                        encoded_url_with_payload = url_with_payload.replace(list_stripped_payload, encoded_stripped_payload)

                                        print(f"{Fore.YELLOW}\n[i] Scanning with payload: {list_stripped_payload}")
                                    print(f"{Fore.GREEN}Vulnerable: {Fore.WHITE}{encoded_url_with_payload}{Fore.CYAN} - Response Time: {response_time:.2f} seconds")
                                    vulnerable_urls.append(url_with_payload)
                                    if single_url_scan and first_vulnerability_prompt:
                                        continue_scan = input(f"{Fore.CYAN}\n[?] Vulnerability found. Do you want to continue testing other payloads? (y/n, press Enter for n): ").strip().lower()
                                        if continue_scan != 'y':
                                            end_time = time.time()
                                            time_taken = end_time - start_time
                                            print(f"{Fore.YELLOW}\n[i] Scanning finished.")
                                            print(f"{Fore.YELLOW}[i] Total found: {len(vulnerable_urls)}")
                                            print(f"{Fore.YELLOW}[i] Total scanned: {total_scanned}")
                                            print(f"{Fore.YELLOW}[i] Time taken: {time_taken:.2f} seconds")

                                            save_prompt(vulnerable_urls)
                                            return
                                        first_vulnerability_prompt = False
                                else:
                                    stripped_payload = url_with_payload.replace(url, '')
                                    encoded_stripped_payload = quote(stripped_payload, safe='')
                                    encoded_url = f"{url}{encoded_stripped_payload}"
                                    if single_url_scan:
                                        print(f"{Fore.YELLOW}\n[i] Scanning with payload: {stripped_payload}")
                                        encoded_url_with_payload = encoded_url
                                    else:
                                        list_stripped_payload = url_with_payload
                                        for url in urls:
                                            list_stripped_payload = list_stripped_payload.replace(url, '')
                                        encoded_stripped_payload = quote(list_stripped_payload, safe='')

                                        encoded_url_with_payload = url_with_payload.replace(list_stripped_payload, encoded_stripped_payload)

                                        print(f"{Fore.YELLOW}\n[i] Scanning with payload: {list_stripped_payload}")
                                    print(f"{Fore.RED}Not Vulnerable: {Fore.WHITE}{encoded_url_with_payload}{Fore.CYAN} - Response Time: {response_time:.2f} seconds")

                    print_scan_summary(len(vulnerable_urls), total_scanned, start_time)
                    save_prompt(vulnerable_urls)

                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}Program terminated by the user!\n")
                    print(f"{Fore.YELLOW}[i] Total found: {len(vulnerable_urls)}")
                    print(f"{Fore.YELLOW}[i] Total scanned: {total_scanned}")
                    print(f"{Fore.YELLOW}[i] Time taken: {time_taken:.2f} seconds")
                    save_prompt(vulnerable_urls)

                    sys.exit(0)

            if __name__ == "__main__":
                sys.excepthook = handle_exception
                main()

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Program terminated by the user!")
            sys.exit(0)


    def run_xss_scanner():
        init(autoreset=True)
        logging.basicConfig(
            filename='xss_scanner.log',
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=logging.INFO
        )

        def colored_logging(message, level='info'):
            """Handle colored console output and logging simultaneously."""
            if level == 'critical':
                print(Fore.RED + message)
                logging.critical(message)
            elif level == 'warning':
                print(Fore.YELLOW + message)
                logging.warning(message)
            else:
                print(Fore.CYAN + message)
                logging.info(message)

        def load_user_agents(yaml_file='config.yaml'):
            """Load user agents from YAML config."""
            try:
                with open(yaml_file, 'r') as file:
                    data = yaml.safe_load(file)
                    return data.get('user_agents', [])
            except FileNotFoundError:
                colored_logging(f"[!] YAML file not found: {yaml_file}", "critical")
                sys.exit(1)
            except yaml.YAMLError as e:
                colored_logging(f"[!] Error parsing YAML file: {e}", "critical")
                sys.exit(1)
                
        def prompt_for_payloads():
            """Prompt user to input payloads or load from a file."""
            payloads = []
            print(Fore.CYAN + "[?] Load payloads from a file or enter manually?")
            print(Fore.CYAN + "[1] Load from a file")
            print(Fore.CYAN + "[2] Enter manually")

            payload_choice = input(Fore.CYAN + "Enter your choice (1 or 2, press Enter for 1): ").strip()
            if payload_choice == '2':
                print(Fore.CYAN + "[i] Enter your payloads, one per line. Enter 'done' to finish:")
                while True:
                    payload = input("Payload: ").strip()
                    if payload.lower() == 'done':
                        break
                    payloads.append(payload)
            else:
                file_path = input(Fore.CYAN + "Enter the file path for payloads: ").strip()
                if os.path.exists(file_path):
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f: 
                            payloads = [line.strip() for line in f.readlines()]
                    except UnicodeDecodeError:
                        print(Fore.RED + "[!] Unicode error while reading the file. Try saving the file in UTF-8 format.")
                        sys.exit(1)
                    except Exception as e:
                        print(Fore.RED + f"[!] Error reading file: {e}")
                        sys.exit(1)
                else:
                    print(Fore.RED + f"[!] File not found: {file_path}")
                    sys.exit(1)

            return payloads
        
        def randomize_payload(payload):
            random_comments = ['<!--random-->', '{#comment#}', '{/*comment*/}', '#random']
            components = payload.split(';')
            random_comments_inserted = [components[0]] + [
                f";{random.choice(random_comments)} {comp}" for comp in components[1:]
            ]
            return ''.join(random_comments_inserted)

        def load_xss_signatures(signature_file='xss_signatures.yaml'):
            """Load common XSS signatures from a YAML file."""
            try:
                with open(signature_file, 'r') as file:
                    return yaml.safe_load(file).get('signatures', [])
            except FileNotFoundError:
                colored_logging(f"[!] Signature file not found: {signature_file}", "critical")
                sys.exit(1)
            except yaml.YAMLError as e:
                colored_logging(f"[!] Error parsing signature file: {e}", "critical")
                sys.exit(1)
                
        def load_xss_dorks(dorks_file='xss_dorks.yaml'):
            """Load XSS dorks for generating vulnerable URLs."""
            try:
                with open(dorks_file, 'r') as file:
                    return yaml.safe_load(file).get('dorks', [])
            except FileNotFoundError:
                colored_logging(f"[!] Dorks file not found: {dorks_file}", "critical")
                sys.exit(1)
            except yaml.YAMLError as e:
                colored_logging(f"[!] Error parsing dorks file: {e}", "critical")
                sys.exit(1)

        def perform_request(url, user_agents, session_cookies=None, auth_token=None):
            """Send a request with random user agents, cookies, and optional auth token."""
            headers = {'User-Agent': random.choice(user_agents)}
            cookies = session_cookies if session_cookies else {}

            if auth_token:
                headers['Authorization'] = f"Bearer {auth_token}"

            try:
                response = requests.get(url, headers=headers, cookies=cookies, timeout=10)
                return response
            except requests.Timeout:
                colored_logging(f"[!] Timeout error: {url}", "warning")
                return None
            except requests.RequestException as e:
                colored_logging(f"[!] Request error: {e}", "critical")
                return None

        def log_response_details(response, payload):
            """Log detailed response information."""
            logging.info(f"Request to {response.url} returned status {response.status_code}")
            logging.info(f"Payload: {payload}")
            logging.info(f"Response Headers: {response.headers}")
            logging.info(f"Response Content Length: {len(response.text)}")
        
        def obfuscate_payload(payload):
            """Obfuscate the payload to evade detection using encoding techniques."""
            encoded_payload = quote(payload)  
            return encoded_payload
        
        def evade_waf_and_ids(payload):
            evasion_techniques = [
                lambda p: urllib.parse.quote(p),  # URL Encoding
                lambda p: p.replace(";", " ; "),  # Space Insertion
                lambda p: p.lower(),  # Case Alteration
            ]

            evaded_payloads = [technique(payload) for technique in evasion_techniques]
            return evaded_payloads

        def save_learned_payload(payload):
            """Save vulnerable payloads to a file for learning mode."""
            with open('learned_payloads.txt', 'a') as f:
                f.write(payload + '\n')

        def load_learned_payloads():
            """Load previously identified vulnerable payloads."""
            if os.path.exists('learned_payloads.txt'):
                with open('learned_payloads.txt', 'r') as f:
                    return [line.strip() for line in f.readlines()]
            return []
        
        def load_error_signatures(yaml_file='error_signatures.yaml'):
            """Load error signatures from a YAML file."""
            try:
                with open(yaml_file, 'r') as file:
                    data = yaml.safe_load(file)
                    return data.get('error_signatures', [])
            except FileNotFoundError:
                colored_logging(f"[!] YAML file not found: {yaml_file}", "critical")
                sys.exit(1)
            except yaml.YAMLError as e:
                colored_logging(f"[!] Error parsing YAML file: {e}", "critical")
                sys.exit(1)



        def check_xss(target_url, payloads, dorks, xss_signatures, max_threads, user_agents, error_signatures, learning_mode=False):
            """Check for XSS vulnerabilities with an optional learning mode for improving future scans."""
            print(f"{Fore.CYAN}[i] Starting XSS scan on: {target_url}")
            total_found = 0
            vulnerable_payloads = []
            vulnerable_urls = []

            learned_payloads = load_learned_payloads() if learning_mode else []

            baseline_response = perform_request(target_url, user_agents)
            baseline_length = len(baseline_response.text) if baseline_response else 0

            def test_payload(payload, dork):
                """Test a single payload with WAF evasion and obfuscation."""
                obfuscated_payload = obfuscate_payload(payload)
                dorked_payload = dork.replace("{payload}", obfuscated_payload)

                for evasion_payload in evade_waf_and_ids(dorked_payload):
                    url = f"{target_url}{evasion_payload}"
                    response = perform_request(url, user_agents)

                    if response:
                        vulnerable, adjusted_payload = analyze_response(response, evasion_payload, baseline_length, xss_signatures, error_signatures)
                        if vulnerable:
                            if learning_mode:
                                save_learned_payload(adjusted_payload)
                            return adjusted_payload, url

                return None, None

            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = {}

                if learning_mode:
                    for payload in learned_payloads:
                        for dork in dorks:
                            futures[executor.submit(test_payload, payload, dork)] = (payload, dork)

                for payload in payloads:
                    for dork in dorks:
                        futures[executor.submit(test_payload, payload, dork)] = (payload, dork)

                for future in as_completed(futures):
                    result, url = future.result()
                    if result and url:
                        total_found += 1
                        vulnerable_payloads.append(result)
                        vulnerable_urls.append(url)
                        colored_logging(f"{Fore.GREEN}[+] Vulnerable with payload: {result}", "info")
                    else:
                        colored_logging(f"{Fore.YELLOW}[-] Not Vulnerable: {url}", "warning")

            return total_found, vulnerable_payloads, vulnerable_urls


        def analyze_response(response, payload, baseline_length, xss_signatures, error_signatures):
            """Analyze response for potential XSS vulnerabilities based on signatures."""
            log_response_details(response, payload)

            if payload in response.text:
                return True, payload

            if abs(len(response.text) - baseline_length) > 100:
                return True, payload

            for signature in xss_signatures:
                if signature in response.text:
                    return True, payload

            for signature in error_signatures:
                if signature in response.text or response.status_code in [500, 502, 503, 504]:
                    return True, payload

            return False, None

        def save_results_to_file(vulnerable_payloads, vulnerable_urls):
            """Save scan results to a text file."""
            filename = f"xss_scan_results_{time.strftime('%Y%m%d-%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write("Vulnerable Payloads:\n")
                f.write('\n'.join(vulnerable_payloads))
                f.write("\n\nVulnerable URLs:\n")
                f.write('\n'.join(vulnerable_urls))
            colored_logging(f"[i] Results saved to {filename}", "info")


        def main():
            """Main function to start the XSS scanner."""
            os.system('cls' if os.name == 'nt' else 'clear')

            title = """
            ███████╗██╗███████╗
            ██╔════╝██║██╔════╝
            ███████╗██║█████╗  
            ╚════██║██║██╔══╝  
            ███████║██║███████╗
            ╚══════╝╚═╝╚══════╝
            """
            print(Fore.GREEN + title)
            print(Fore.YELLOW + "Welcome to the Genesis XSS Scanner")

            target_url = input(Fore.CYAN + "[?] Enter the target URL: ").strip()
            user_agents = load_user_agents()
            payloads = prompt_for_payloads()
            dorks = load_xss_dorks()
            xss_signatures = load_xss_signatures()
            error_signatures = load_error_signatures()

            learning_mode = input(Fore.CYAN + "[?] Enable learning mode? (y/n): ").strip().lower() == 'y'

            max_threads = int(input(Fore.CYAN + "[?] Enter the number of threads to use (default 5): ").strip() or "5")

            total_found, vulnerable_payloads, vulnerable_urls = check_xss(
                target_url, payloads, dorks, xss_signatures, max_threads, user_agents, error_signatures, learning_mode
            )
            save_results_to_file(vulnerable_payloads, vulnerable_urls)

        if __name__ == "__main__":
            main()


    def run_or_scanner():

        try:
            init(autoreset=True)

            def check_and_install_packages(packages):
                for package, version in packages.items():
                    try:
                        __import__(package)
                    except ImportError:
                        subprocess.check_call([sys.executable, '-m', 'pip', 'install', f"{package}=={version}"])

            def test_open_redirect(url, payloads, success_criteria, max_threads=5):
                def check_payload(payload):
                    target_url = f"{url}{payload.strip()}"
                    
                    try:
                        response = requests.get(target_url, allow_redirects=False)
                        result = None
                        is_vulnerable = False
                        
                        if 'Location' in response.headers:
                            location = response.headers['Location']
                            is_vulnerable = any(crit in location for crit in success_criteria)
                            if is_vulnerable:
                                result = Fore.GREEN + f"[+] Vulnerable: {target_url} redirects to {location}"
                            else:
                                result = Fore.RED + f"[-] Not Vulnerable: {target_url}"
                        else:
                            result = Fore.RED + f"[-] No Redirect: {target_url}"

                        return result, is_vulnerable
                    except requests.exceptions.RequestException:
                        result = Fore.RED + f"[-] No Redirect: {target_url}"
                        return result, False

                found_vulnerabilities = 0
                vulnerable_urls = []
                with ThreadPoolExecutor(max_workers=max_threads) as executor:
                    future_to_payload = {executor.submit(check_payload, payload): payload for payload in payloads}
                    for future in as_completed(future_to_payload):
                        payload = future_to_payload[future]
                        try:
                            result, is_vulnerable = future.result()
                            if result:
                                print(Fore.YELLOW + f"\n[i] Scanning with payload: {payload.strip()}")
                                print(result)
                                if is_vulnerable:
                                    found_vulnerabilities += 1
                                    vulnerable_urls.append(url + payload.strip())
                        except Exception as e:
                            print(Fore.RED + f"[!] Exception occurred for payload {payload}: {str(e)}")
                return found_vulnerabilities, vulnerable_urls

            def save_results(vulnerable_urls):
                save_prompt(vulnerable_urls)

            def save_prompt(vulnerable_urls=[]):
                save_choice = input(Fore.CYAN + "\n[?] Do you want to save the vulnerable URLs to a file? (y/n, press Enter for n): ").strip().lower()
                if save_choice == 'y':
                    output_file = input(Fore.CYAN + "Enter the name of the output file (press Enter for 'vulnerable_urls.txt'): ").strip() or 'vulnerable_urls.txt'
                    with open(output_file, 'w') as f:
                        for url in vulnerable_urls:
                            f.write(url + '\n')
                    print(Fore.GREEN + f"Vulnerable URLs have been saved to {output_file}")
                    os._exit(0)
                else:
                    print(Fore.YELLOW + "Vulnerable URLs will not be saved.")
                    os._exit(0)

            def prompt_for_urls():
                while True:
                    try:
                        url_input = get_file_path("[?] Enter the path to the input file containing the URLs (or press Enter to input a single URL): ")
                        if url_input:
                            if not os.path.isfile(url_input):
                                raise FileNotFoundError(f"File not found: {url_input}")
                            with open(url_input) as file:
                                urls = [line.strip() for line in file if line.strip()]
                            return urls
                        else:
                            single_url = input(Color.BLUE + "[?] Enter a single URL to scan: ").strip()
                            if single_url:
                                return [single_url]
                            else:
                                print(Fore.RED + "[!] You must provide either a file with URLs or a single URL.")
                                input(Fore.YELLOW + "\n[i] Press Enter to try again...")
                                clear_screen()
                                print(Fore.GREEN + "Welcome to the Open Redirect Testing Tool!\n")
                    except Exception as e:
                        print(Fore.RED + f"[!] Error reading input file: {url_input}. Exception: {str(e)}")
                        input(Fore.YELLOW + "[i] Press Enter to try again...")
                        clear_screen()
                        print(Fore.GREEN + "Welcome to the Open Redirect Testing Tool!\n")

            def prompt_for_payloads():
                while True:
                    try:
                        payload_input = get_file_path("[?] Enter the path to the payloads file: ")
                        if not os.path.isfile(payload_input):
                            raise FileNotFoundError(f"File not found: {payload_input}")
                        with open(payload_input) as file:
                            payloads = [line.strip() for line in file if line.strip()]
                        return payloads
                    except Exception as e:
                        print(Fore.RED + f"[!] Error reading payload file: {payload_input}. Exception: {str(e)}")
                        input(Fore.YELLOW + "[i] Press Enter to try again...")
                        clear_screen()
                        print(Fore.GREEN + "Welcome to the Open Redirect Testing Tool!\n")

            def print_scan_summary(total_found, total_scanned, start_time):
                print(Fore.YELLOW + "\n[i] Scanning finished.")
                print(Fore.YELLOW + f"[i] Total found: {total_found}")
                print(Fore.YELLOW + f"[i] Total scanned: {total_scanned}")
                print(Fore.YELLOW + f"[i] Time taken: {int(time.time() - start_time)} seconds")

            def clear_screen():
                os.system('cls' if os.name == 'nt' else 'clear')

            def get_file_path(prompt_text):
                completer = PathCompleter()
                return prompt(prompt_text, completer=completer).strip()

            def main():
                clear_screen()

                required_packages = {
                    'requests': '2.28.1',
                    'prompt_toolkit': '3.0.36',
                    'colorama': '0.4.6'
                }
                check_and_install_packages(required_packages)

                time.sleep(3)
                clear_screen()


                panel = Panel(
                """
  ____  ___    ____________   _  ___  __________
 / __ \/ _ \  / __/ ___/ _ | / |/ / |/ / __/ _  |
/ /_/ / , _/ _\ \/ /__/ __ |/    /    / _// , _/
\____/_/|_| /___/\___/_/ |_/_/|_/_/|_/___/_/|_| 
                                                
                                                        
                    """,
                style="bold green",
                border_style="blue",
                expand=False
                )
                rich_print(panel, "\n")
                
                print(Fore.GREEN + "Welcome to the Open Redirect Testing Tool!\n")

                urls = prompt_for_urls()
                payloads = prompt_for_payloads()
                success_criteria_input = input("[?] Enter the success criteria patterns (comma-separated, e.g: 'https://google.com,redirected.com', press Enter for 'https://google.com'): ").strip()
                success_criteria = [pattern.strip() for pattern in success_criteria_input.split(',')] if success_criteria_input else ['https://google.com']
                
                max_threads_input = input("[?] Enter the number of concurrent threads (0-10, press Enter for 5): ").strip()
                max_threads = int(max_threads_input) if max_threads_input.isdigit() and 0 <= int(max_threads_input) <= 10 else 5

                print(Fore.YELLOW + "\n[i] Loading, Please Wait...")
                time.sleep(3)
                clear_screen()
                print(Fore.CYAN + "[i] Starting scan...\n")

                total_found = 0
                total_scanned = 0
                start_time = time.time()
                vulnerable_urls = []

                if payloads:
                    for url in urls:
                        print(Fore.YELLOW + f"\n[i] Scanning URL: {url}\n")
                        found, urls_with_payloads = test_open_redirect(url, payloads, success_criteria, max_threads)
                        total_found += found
                        total_scanned += len(payloads)
                        vulnerable_urls.extend(urls_with_payloads)
                
                print_scan_summary(total_found, total_scanned, start_time)
                
                save_results(vulnerable_urls)

            if __name__ == "__main__":
                try:
                    main()
                except KeyboardInterrupt:
                    print(Fore.YELLOW + "\nProgram terminated by the user!")
                    sys.exit(0)
                except Exception as e:
                    print(Fore.RED + f"[!] An unexpected error occurred: {e}")
                    sys.exit(1)

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Program terminated by the user!")
            sys.exit(0)


    def run_lfi_scanner():

        init(autoreset=True)

        def check_and_install_packages(packages):
            for package, version in packages.items():
                try:
                    __import__(package)
                except ImportError:
                    subprocess.check_call([sys.executable, '-m', 'pip', 'install', f"{package}=={version}"])

        def test_lfi(url, payloads, success_criteria, max_threads=5):
            def check_payload(payload):
                encoded_payload = urllib.parse.quote(payload.strip())
                target_url = f"{url}{encoded_payload}"
                start_time = time.time()
                
                try:
                    response = requests.get(target_url)
                    response_time = round(time.time() - start_time, 2)
                    result = None
                    is_vulnerable = False
                    if response.status_code == 200:
                        is_vulnerable = any(re.search(pattern, response.text) for pattern in success_criteria)
                        if is_vulnerable:
                            result = Fore.GREEN + f"[+] Vulnerable: {Fore.WHITE} {target_url} {Fore.CYAN} - Response Time: {response_time} seconds"
                        else:
                            result = Fore.RED + f"[-] Not Vulnerable: {Fore.WHITE} {target_url} {Fore.CYAN} - Response Time: {response_time} seconds"
                    else:
                        result = Fore.RED + f"[-] Not Vulnerable: {Fore.WHITE} {target_url} {Fore.CYAN} - Response Time: {response_time} seconds"

                    return result, is_vulnerable
                except requests.exceptions.RequestException as e:
                    print(Fore.RED + f"[!] Error accessing {target_url}: {str(e)}")
                    return None, False

            found_vulnerabilities = 0
            vulnerable_urls = []
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                future_to_payload = {executor.submit(check_payload, payload): payload for payload in payloads}
                for future in as_completed(future_to_payload):
                    payload = future_to_payload[future]
                    try:
                        result, is_vulnerable = future.result()
                        if result:
                            print(Fore.YELLOW + f"\n[i] Scanning with payload: {payload.strip()}")
                            print(result)
                            if is_vulnerable:
                                found_vulnerabilities += 1
                                vulnerable_urls.append(url + urllib.parse.quote(payload.strip()))
                    except Exception as e:
                        print(Fore.RED + f"[!] Exception occurred for payload {payload}: {str(e)}")
            return found_vulnerabilities, vulnerable_urls

        def save_results(vulnerable_urls):
            save_prompt(vulnerable_urls)

        def save_prompt(vulnerable_urls=[]):
            save_choice = input(Fore.CYAN + "\n[?] Do you want to save the vulnerable URLs to a file? (y/n, press Enter for n): ").strip().lower()
            if save_choice == 'y':
                output_file = input(Fore.CYAN + "Enter the name of the output file (press Enter for 'vulnerable_urls.txt'): ").strip() or 'vulnerable_urls.txt'
                with open(output_file, 'w') as f:
                    for url in vulnerable_urls:
                        f.write(url + '\n')
                print(Fore.GREEN + f"Vulnerable URLs have been saved to {output_file}")
            else:
                print(Fore.YELLOW + "Vulnerable URLs will not be saved.")

        def prompt_for_urls():
            while True:
                try:
                    url_input = get_file_path("[?] Enter the path to the input file containing the URLs (or press Enter to input a single URL): ")
                    if url_input:
                        if not os.path.isfile(url_input):
                            raise FileNotFoundError(f"File not found: {url_input}")
                        with open(url_input) as file:
                            urls = [line.strip() for line in file if line.strip()]
                        return urls
                    else:
                        single_url = input(Fore.CYAN + "[?] Enter a single URL to scan: ").strip()
                        if single_url:
                            return [single_url]
                        else:
                            print(Fore.RED + "[!] You must provide either a file with URLs or a single URL.")
                            input(Fore.YELLOW + "\n[i] Press Enter to try again...")
                            clear_screen()
                            print(Fore.GREEN + "Welcome to the LFI Testing Tool!\n")
                except Exception as e:
                    print(Fore.RED + f"[!] Error reading input file: {url_input}. Exception: {str(e)}")
                    input(Fore.YELLOW + "[i] Press Enter to try again...")
                    clear_screen()
                    print(Fore.GREEN + "Welcome to the LFI Testing Tool!\n")

        def prompt_for_payloads():
            while True:
                try:
                    payload_input = get_file_path("[?] Enter the path to the payloads file: ")
                    if not os.path.isfile(payload_input):
                        raise FileNotFoundError(f"File not found: {payload_input}")
                    with open(payload_input) as file:
                        payloads = [line.strip() for line in file if line.strip()]
                    return payloads
                except Exception as e:
                    print(Fore.RED + f"[!] Error reading payload file: {payload_input}. Exception: {str(e)}")
                    input(Fore.YELLOW + "[i] Press Enter to try again...")
                    clear_screen()
                    print(Fore.GREEN + "Welcome to the LFI Testing Tool!\n")

        def print_scan_summary(total_found, total_scanned, start_time):
            print(Fore.YELLOW + "\n[i] Scanning finished.")
            print(Fore.YELLOW + f"[i] Total found: {total_found}")
            print(Fore.YELLOW + f"[i] Total scanned: {total_scanned}")
            print(Fore.YELLOW + f"[i] Time taken: {int(time.time() - start_time)} seconds")
            exit()

        def clear_screen():
            os.system('cls' if os.name == 'nt' else 'clear')

        def get_file_path(prompt_text):
            completer = PathCompleter()
            return prompt(prompt_text, completer=completer).strip()

        def main():
            clear_screen()

            required_packages = {
                'requests': '2.28.1',
                'prompt_toolkit': '3.0.36',
                'colorama': '0.4.6'
            }
            check_and_install_packages(required_packages)

            time.sleep(3)
            clear_screen()

            panel = Panel(
            """
    __    __________   _____                                 
   / /   / ____/  _/  / ___/_________ _____  ____  ___  _____
  / /   / /_   / /    \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / /___/ __/ _/ /    ___/ / /__/ /_/ / / / / / / /  __/ /    
 /_____/_/   /___/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
                                                            
                                                      
                """,
            style="bold green",
            border_style="blue",
            expand=False
            )
            rich_print(panel, "\n")

            
            print(Fore.GREEN + "Welcome to the LFI Testing Tool!\n")

            urls = prompt_for_urls()
            payloads = prompt_for_payloads()
            success_criteria_input = input("[?] Enter the success criteria patterns (comma-separated, e.g: 'root:,admin:', press Enter for 'root:'): ").strip()
            success_criteria = [pattern.strip() for pattern in success_criteria_input.split(',')] if success_criteria_input else ['root:']
            
            max_threads_input = input("[?] Enter the number of concurrent threads (0-10, press Enter for 5): ").strip()
            max_threads = int(max_threads_input) if max_threads_input.isdigit() and 0 <= int(max_threads_input) <= 10 else 5

            print(Fore.YELLOW + "\n[i] Loading, Please Wait...")
            time.sleep(3)
            clear_screen()
            print(Fore.CYAN + "[i] Starting scan...\n")

            total_found = 0
            total_scanned = 0
            start_time = time.time()
            vulnerable_urls = []

            if payloads:
                for url in urls:
                    print(Fore.YELLOW + f"\n[i] Scanning URL: {url}\n")
                    found, urls_with_payloads = test_lfi(url, payloads, success_criteria, max_threads)
                    total_found += found
                    total_scanned += len(payloads)
                    vulnerable_urls.extend(urls_with_payloads)


            print_scan_summary(total_found, total_scanned, start_time)
            
            save_results(vulnerable_urls)

        if __name__ == "__main__":
            try:
                main()
            except KeyboardInterrupt:
                sys.exit(0)
            except Exception as e:
                print(Fore.RED + f"[!] An unexpected error occurred: {e}")
                sys.exit(1)


    def run_ssrf_scanner():
        init(autoreset=True)
        logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)

        def load_config(config_file='config.yaml'):
            if not os.path.exists(config_file):
                logger.error(Fore.RED + f"Config file {config_file} not found.")
                sys.exit(1)
            try:
                with open(config_file, 'r') as f:
                    return yaml.safe_load(f)
            except yaml.YAMLError as e:
                logger.error(Fore.RED + f"Error reading config file: {e}")
                sys.exit(1)

        def get_random_user_agent():
            config = load_config()
            USER_AGENTS = config.get('user_agents', [])
            return random.choice(USER_AGENTS) if USER_AGENTS else 'Mozilla/5.0'

        def get_file_path(prompt_text):
            return input(Fore.CYAN + prompt_text).strip()

        def clear_screen():
            os.system('cls' if os.name == 'nt' else 'clear')

        def save_results(vulnerable_payloads, vulnerable_urls, output_file="vulnerable_results.json"):
            if not vulnerable_payloads and not vulnerable_urls:
                logger.info(Fore.YELLOW + "No vulnerable payloads or URLs to save.")
                return
            results = {
                "vulnerable_payloads": vulnerable_payloads,
                "vulnerable_urls": vulnerable_urls
            }
            try:
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=4)
                logger.info(Fore.GREEN + f"Vulnerable payloads and URLs saved to {output_file}")
            except Exception as e:
                logger.error(Fore.RED + f"Error saving results: {e}")

        def get_http_session(retries=3, backoff_factor=0.3, timeout=5):
            session = requests.Session()
            retry_strategy = Retry(
                total=retries,
                backoff_factor=backoff_factor,
                status_forcelist=[500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            return session

        def perform_request(url, method='GET', headers=None, proxy=None, timeout=5):
            session = get_http_session(timeout=timeout)
            try:
                logger.info(Fore.BLUE + f"Sending {method} request to {url}")
                response = session.request(method, url, headers=headers or {'User-Agent': get_random_user_agent()}, proxies=proxy, timeout=timeout)
                logger.info(Fore.BLUE + f"Received response with status code {response.status_code}")
                return response
            except requests.exceptions.Timeout:
                logger.error(Fore.RED + f"Request to {url} timed out.")
            except requests.exceptions.ConnectionError:
                logger.error(Fore.RED + f"Connection error occurred for {url}.")
            except requests.exceptions.RequestException as e:
                logger.error(Fore.RED + f"Request to {url} failed: {e}")
            return None

        def resolve_hostname(hostname):
            try:
                parsed_url = urlparse(hostname)
                host = parsed_url.hostname if parsed_url.hostname else hostname

                logger.info(Fore.GREEN + f"Attempting to resolve hostname: {host}")

                addr_info = socket.getaddrinfo(host, None)
                ip_addresses = list(set([info[4][0] for info in addr_info]))
                logger.info(Fore.GREEN + f"Resolved {host} to IP addresses: {ip_addresses}")
                return ip_addresses
            except socket.gaierror as e:
                logger.error(Fore.RED + f"Failed to resolve the hostname {hostname}: {e}")
                return []

        def verify_ssrf_payload(target_url, payload, target_host, external_callback_url, proxy=None):
            logger.info(Fore.GREEN + f"Verifying SSRF payload: {payload} at {target_url}")

            target_ips = resolve_hostname(target_host)
            if not target_ips:
                logger.error(Fore.RED + f"Hostname resolution failed for {target_host}. Skipping this test.")
                return False, None

            open_ports = []
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = []
                for ip in target_ips:
                    for port in range(1, 65536):
                        futures.append(executor.submit(scan_port, ip, port))
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        open_ports.append(result)

            if open_ports:
                logger.info(Fore.GREEN + f"Open ports found: {open_ports}")
            else:
                logger.info(Fore.YELLOW + "No open ports found.")

            payload_url = f"{target_url}?url={external_callback_url}"
            response = perform_request(payload_url, proxy=proxy)

            if response:
                logger.info(Fore.GREEN + f"SSRF verified by DNS logging with payload: {payload_url}")
                return True, payload_url
            return False, None

        def scan_port(ip, port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        return port
            except Exception as e:
                logger.debug(Fore.RED + f"Error scanning port {port} on {ip}: {e}")
            return None

        def prompt_for_input(prompt_type):
            """
            Handles input for URLs and hostnames, allowing file or single input.
            """
            while True:
                try:
                    input_choice = input(Fore.CYAN + f"[?] Enter the path to the {prompt_type} file (or press Enter to input a single {prompt_type}): ").strip()
                    if input_choice:
                        if not os.path.isfile(input_choice):
                            raise FileNotFoundError(f"File not found: {input_choice}")
                        with open(input_choice, 'r', encoding='utf-8') as file:
                            items = [line.strip() for line in file if line.strip()]
                        if items:
                            return items
                        else:
                            print(Fore.RED + f"[!] The file is empty or contains invalid {prompt_type}.")
                    else:
                        single_item = input(Fore.CYAN + f"[?] Enter a single {prompt_type}: ").strip()
                        if single_item:
                            return [single_item]
                        else:
                            print(Fore.RED + f"[!] You must provide either a file with {prompt_type} or a single {prompt_type}.")
                            input(Fore.YELLOW + "\n[i] Press Enter to try again...")
                            clear_screen()
                            print(Fore.GREEN + "Welcome to the Genesis SSRF Scanner!\n") #cnc

                except FileNotFoundError as e:
                    print(Fore.RED + f"[!] Error: {str(e)}")
                    input(Fore.YELLOW + "[i] Press Enter to try again...")
                    clear_screen()
                    print(Fore.GREEN + "Welcome to the Genesis SSRF Scanner!\n") #cnc
                except Exception as e:
                    print(Fore.RED + f"[!] Error reading input file: {input_choice}. Exception: {str(e)}")
                    input(Fore.YELLOW + "[i] Press Enter to try again...")
                    clear_screen()
                    print(Fore.GREEN + "Welcome to the Genesis SSRF Scanner!\n") #cnc

        def prompt_for_payloads():
            payloads = []
            print(f"{Fore.CYAN}[?] Do you want to enter payloads manually or load from a file?")
            choice = input(f"{Fore.CYAN}[M]anual or [F]ile? (press Enter for Manual): ").strip().lower()
            if choice == 'f':
                file_path = input(f"{Fore.CYAN}[?] Enter the path to the payloads file: ").strip()
                if not os.path.isfile(file_path):
                    print(f"{Fore.RED}[!] File not found: {file_path}")
                    sys.exit(1)
                with open(file_path, encoding='utf-8') as file:
                    payloads = [line.strip() for line in file if line.strip()]
            else:
                print(f"{Fore.CYAN}[?] Enter the SSRF payloads one by one. Type 'done' when finished.")
                while True:
                    payload = input(f"{Fore.CYAN}Enter payload: ").strip()
                    if payload.lower() == 'done':
                        break
                    if payload:
                        payloads.append(payload)
            return payloads

        def prompt_for_callback_url():
            callback_url = input(Fore.CYAN + "[?] Enter the external callback URL to be used for SSRF detection: ").strip()
            if not callback_url:
                logger.error(Fore.RED + "No callback URL provided. Exiting...")
                sys.exit(1)
            return callback_url

        def check_ssrf(target_url, payloads, target_host, external_callback_url, max_threads, proxy=None):
            logger.info(Fore.BLUE + f"Starting SSRF scan for {target_url} with payloads.")
            total_found = 0
            vulnerable_payloads = []
            vulnerable_urls = []

            def test_payload(payload):
                is_vulnerable, vulnerable_url = verify_ssrf_payload(target_url, payload, target_host, external_callback_url, proxy)
                if is_vulnerable:
                    logger.info(Fore.GREEN + f"SSRF vulnerability detected: {vulnerable_url}")
                    vulnerable_payloads.append(payload)
                    vulnerable_urls.append(vulnerable_url)
                    return True
                return False

            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = {executor.submit(test_payload, payload): payload for payload in payloads}
                for future in as_completed(futures):
                    if future.result():
                        total_found += 1

            logger.info(Fore.BLUE + f"Total vulnerabilities found: {total_found}")
            save_results(vulnerable_payloads, vulnerable_urls)

        def main():
            clear_screen()
            print(Fore.GREEN + r"""
        _____                                 _____ _____  _____  ______
        / ____|                               / ____|  __ \|  __ \|  ____|
        | |  __  ___   ___   ___   _ __  _   _| (___ | |__) | |__) | |__
        | | |_ |/ _ \ / _ \ / _ \ | '_ \| | | |\___ \|  ___/|  ___/|  __|
        | |__| | (_) | (_) | (_) || | | | |_| |____) | |    | |    | |____
        \_____|\___/ \___/ \___/ |_| |_|\__, |_____/|_|    |_|    |______|
                                        __/ |
                                        |___/

            """)
            print(Fore.GREEN + "[*] Welcome to the Genesis SSRF Scanner! Automated SSRF vulnerability detection tool.") #cnc
            
            urls = prompt_for_input("URLs")
            hosts = prompt_for_input("hostnames")
            
            payloads = prompt_for_payloads()

            callback_url = prompt_for_callback_url()

            max_threads = 10
            proxy = None

            for target_url, target_host in zip(urls, hosts):
                check_ssrf(target_url, payloads, target_host, callback_url, max_threads, proxy)

        if __name__ == "__main__":
            main()
                

    def run_ssti_scanner():
        logging.basicConfig(
            filename='ssti_scanner.log',
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=logging.INFO
        )
        logging.info("logging is working")

        init(autoreset=True)

        def colored_logging(message, level='info'):
            if level == 'critical':
                print(Fore.RED + message)
                logging.critical(message)
            elif level == 'warning':
                print(Fore.YELLOW + message)
                logging.warning(message)
            else:
                print(Fore.CYAN + message)
                logging.info(message)

        def load_user_agents(yaml_file='config.yaml'):
            try:
                with open(yaml_file, 'r') as file:
                    data = yaml.safe_load(file)
                    return data.get('user_agents', [])
            except FileNotFoundError:
                colored_logging(f"[!] YAML file not found: {yaml_file}", "critical")
                sys.exit(1)
            except yaml.YAMLError as e:
                colored_logging(f"[!] Error parsing YAML file: {e}", "critical")
                sys.exit(1)

        def perform_request(url, user_agents, session_cookies=None, auth_token=None):
            headers = {'User-Agent': random.choice(user_agents)}
            cookies = session_cookies if session_cookies else {}
            
            if auth_token:
                headers['Authorization'] = f"Bearer {auth_token}"

            try:
                response = requests.get(url, headers=headers, cookies=cookies, timeout=10)
                return response
            except requests.Timeout:
                colored_logging(f"[!] Timeout error: {url}", "warning")
                return None
            except requests.RequestException as e:
                colored_logging(f"[!] Request error: {e}", "critical")
                return None

        def randomize_payload(payload):
            random_comments = ['<!--random-->', '{#comment#}', '{/*comment*/}', '#random']
            components = payload.split('{{')
            random_comments_inserted = [components[0]] + [
                f"{{{{{random.choice(random_comments)} {comp}}}" for comp in components[1:]
            ]
            return ''.join(random_comments_inserted)
        
        def evade_waf_and_ids(payload):
            evasion_techniques = [
                lambda p: p.replace("{{", "%7B%7B").replace("}}", "%7D%7D"),  # URL Encoding
                lambda p: p.replace("{{", "&#123;&#123;").replace("}}", "&#125;&#125;"),  # Unicode Encoding
                lambda p: f"{{{{!--{p}--}}}}",  # HTML Comment Injection
                lambda p: p.lower(),  # Case Alteration
            ]

            evaded_payloads = [technique(payload) for technique in evasion_techniques]
            return evaded_payloads

        def analyze_response(response, payload, baseline_length):
            error_signatures = [
                r"Traceback \(most recent call last\):",  # Python Traceback
                r"Fatal error",                           # PHP Errors
                r"Exception in thread",                   # Java Errors
                r"org\.apache\.velocity",                 # Velocity Template Errors
                r"Error occurred in template processing", # Freemarker Errors
                r"TemplateSyntaxError",                  # General template engine errors
            ]

            for signature in error_signatures:
                if re.search(signature, response.text, re.IGNORECASE):
                    return True

            if abs(len(response.text) - baseline_length) > 100:
                return True
            if response.status_code in [500, 502, 503, 504]:
                return True

            if "{{7*7}}" in payload and "49" in response.text:
                return True

            if "{{" in response.text or "{%" in response.text:
                return True

            return False

        def check_ssti(target_url, payloads, max_threads, user_agents):
            print(f"{Fore.CYAN}[i] Starting SSTI scan on: {target_url}")
            total_found = 0
            vulnerable_payloads = []
            vulnerable_urls = []

            baseline_response = perform_request(target_url, user_agents)
            baseline_length = len(baseline_response.text) if baseline_response else 0

            def test_payload(payload):
                randomized_payload = randomize_payload(payload)
                for evasion_payload in evade_waf_and_ids(randomized_payload):
                    url = f"{target_url}/?input={evasion_payload}"
                    response = perform_request(url, user_agents)

                    if response and analyze_response(response, payload, baseline_length):
                        print(f"{Fore.GREEN}[+] Vulnerable with payload: {evasion_payload}")
                        return evasion_payload, url
                    
                print(f"{Fore.YELLOW}[-] Not Vulnerable: {url}")
                return None, None

            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = {executor.submit(test_payload, payload): payload for payload in payloads}
                for future in as_completed(futures):
                    result, url = future.result()
                    if result and url:
                        total_found += 1
                        vulnerable_payloads.append(result)
                        vulnerable_urls.append(url)

            return total_found, vulnerable_payloads, vulnerable_urls

        async def async_request(url, user_agents, session_cookie=None, auth_token=None, timeout=10):
            headers = {'User-Agent': random.choice(user_agents)}
            if session_cookie:
                headers['Cookie'] = session_cookie
            if auth_token:
                headers['Authorization'] = f"Bearer {auth_token}"

            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(url, headers=headers, timeout=timeout) as response:
                        return await response.text(), response.status
                except asyncio.TimeoutError:
                    colored_logging(f"[!] Timeout error: {url}", "warning")
                    return None, None
                except aiohttp.ClientError as e:
                    colored_logging(f"[!] Async request error: {e}", "critical")
                    return None, None

        async def test_payload_async(payload, target_url, baseline_length, user_agents):
            randomized_payload = randomize_payload(payload)
            for evasion_payload in evade_waf_and_ids(randomized_payload):
                url = f"{target_url}/?input={evasion_payload}"
                response_text, status_code = await async_request(url, user_agents)
                if response_text:
                    response = type('Response', (), {'status_code': status_code, 'text': response_text})
                    if analyze_response(response, payload, baseline_length):
                        colored_logging(f"[+] Vulnerable with payload: {payload}", "info")
                        return payload, url
            colored_logging(f"[-] Not Vulnerable: {url}", "warning")
            return None, None

        async def check_ssti_async(target_url, payloads, user_agents):
            baseline_response = perform_request(target_url, user_agents)
            baseline_length = len(baseline_response.text) if baseline_response else 0
            tasks = []
            for payload in payloads:
                tasks.append(test_payload_async(payload, target_url, baseline_length, user_agents))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            return results

        def adjust_payloads_for_engine(engine, payloads):
            engine_specific_payloads = {
                'Jinja2': [p.replace('{{', '{{').replace('}}', '}}') for p in payloads],
                'Twig': [p.replace('{{', '{{').replace('}}', '}}') for p in payloads],
                'Smarty': [p.replace('{{', '{php}').replace('}}', '{/php}') for p in payloads],
                'Blade': [p.replace('{{', '@php echo ').replace('}}', '; @endphp') for p in payloads],
                'Pug': [p.replace('{{', '#{').replace('}}', '}') for p in payloads],
                'Liquid': [p.replace('{{', '{{').replace('}}', '}}') for p in payloads],
                'Freemarker': [p.replace('{{', '${').replace('}}', '}') for p in payloads],
                'Mustache': [p.replace('{{', '{{').replace('}}', '}}') for p in payloads],
                'Mako': [p.replace('{{', '${').replace('}}', '}') for p in payloads],
                'Velocity': [p.replace('{{', '${').replace('}}', '}') for p in payloads],
                'Dot': [p.replace('{{', '{{= ').replace('}}', '}}') for p in payloads],
                'Dust': [p.replace('{{', '{').replace('}}', '}') for p in payloads],
                'EJS': [p.replace('{{', '<%= ').replace('}}', ' %>') for p in payloads],
                'Marko': [p.replace('{{', '${').replace('}}', '}') for p in payloads],
                'Nunjucks': [p.replace('{{', '{{').replace('}}', '}}') for p in payloads],
                'Tornado': [p.replace('{{', '{{').replace('}}', '}}') for p in payloads],
                'ERB': [p.replace('{{', '<%= ').replace('}}', ' %>') for p in payloads],
                'Slim': [p.replace('{{', '#{').replace('}}', '}') for p in payloads],
                'Channel': [p.replace('{{', '{{').replace('}}', '}}') for p in payloads],
                'Handlebars': [p.replace('{{', '{{').replace('}}', '}}') for p in payloads],
                'Thymeleaf': [p.replace('{{', 'th:text="${').replace('}}', '}"') for p in payloads],
                'GoTemplate': [p.replace('{{', '{{').replace('}}', '}}') for p in payloads],
                'Razor': [p.replace('{{', '@(').replace('}}', ')') for p in payloads],
                'Pebble': [p.replace('{{', '{{').replace('}}', '}}') for p in payloads],
                'JSP': [p.replace('{{', '<%= ').replace('}}', ' %>') for p in payloads],
                'HAML': [p.replace('{{', '#{').replace('}}', '}') for p in payloads],
                'ApacheTiles': [p.replace('{{', '#{').replace('}}', '}') for p in payloads],
                'XSLT': [p.replace('{{', '<xsl:value-of select="').replace('}}', '"/>') for p in payloads],
                'Soy': [p.replace('{{', '{msg desc="').replace('}}', '"}{/msg}') for p in payloads],
                'HTMX': [p.replace('{{', '{{').replace('}}', '}}') for p in payloads],
                'Svelte': [p.replace('{{', '{').replace('}}', '}') for p in payloads],
                'Plates': [p.replace('{{', '{{').replace('}}', '}}') for p in payloads],
            }

            if engine in engine_specific_payloads:
                adjusted_payloads = engine_specific_payloads[engine]
                print(f"[i] Adjusted payloads for {engine} engine.")
                return adjusted_payloads
            else:
                print(f"[!] No specific adjustments for engine: {engine}. Using default payloads.")
                return payloads

        def load_template_engines(yaml_file='engines.yaml'):
            try:
                with open(yaml_file, 'r') as file:
                    return yaml.safe_load(file)
            except FileNotFoundError:
                colored_logging(f"[!] YAML file not found: {yaml_file}", "critical")
                sys.exit(1)
            except yaml.YAMLError as e:
                colored_logging(f"[!] Error parsing YAML file: {e}", "critical")
                sys.exit(1)

        def detect_template_engine_dynamic(target_url, user_agents, engines_payload_file='engines.yaml'):
            colored_logging("[i] Attempting dynamic template engine detection...", "info")

            engine_payloads = load_template_engines(engines_payload_file)

            for engine, payload in engine_payloads.items():
                response = perform_request(f"{target_url}/?input={payload}", user_agents)
                if response and '49' in response.text:  
                    colored_logging(f"[+] Detected {engine} template engine by dynamic detection!", "info")
                    return engine

            colored_logging("[!] Could not detect any template engine.", "warning")
            return None


        def prompt_for_payloads(engine=None):
            payloads = []
            print(Fore.CYAN + "[?] Load payloads from a file or enter manually?")
            print(Fore.CYAN + "[1] Load from a file")
            print(Fore.CYAN + "[2] Enter manually")

            payload_choice = input(Fore.CYAN + "Enter your choice (1 or 2, press Enter for 1): ").strip()
            if payload_choice == '2':
                print(Fore.CYAN + "[i] Enter your payloads, one per line. Enter 'done' to finish:")
                while True:
                    payload = input("Payload: ").strip()
                    if payload.lower() == 'done':
                        break
                    payloads.append(payload)
            else:
                file_path = input(Fore.CYAN + "Enter the file path for payloads: ").strip()
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        payloads = [line.strip() for line in f.readlines()]
                else:
                    print(Fore.RED + f"[!] File not found: {file_path}")
                    sys.exit(1)

            if engine:
                payloads = adjust_payloads_for_engine(engine, payloads)

            return payloads

        def save_results_to_file(vulnerable_payloads, vulnerable_urls):
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = f"ssti_scan_results_{timestamp}.txt"
            with open(filename, 'w') as f:
                f.write("Vulnerable Payloads:\n")
                f.write('\n'.join(vulnerable_payloads))
                f.write("\n\nVulnerable URLs:\n")
                f.write('\n'.join(vulnerable_urls))
            colored_logging(f"[i] Results saved to {filename}", "info")
            
        def generate_detailed_report(vulnerable_payloads, vulnerable_urls):
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            report_filename = f"ssti_detailed_report_{timestamp}.txt"

            with open(report_filename, 'w') as f:
                f.write("=== SSTI Detailed Vulnerability Report ===\n")
                f.write(f"Scan conducted on: {timestamp}\n\n")

                for i, (payload, url) in enumerate(zip(vulnerable_payloads, vulnerable_urls)):
                    f.write(f"Vulnerability {i+1}:\n")
                    f.write(f"URL: {url}\n")
                    f.write(f"Payload: {payload}\n")
                    
                    risk_level = assess_risk(payload)
                    f.write(f"Risk Level: {risk_level}\n")
                    
                    remediation_steps = suggest_remediation(payload)
                    f.write(f"Remediation: {remediation_steps}\n\n")
                    vulnerability_category = categorize_vulnerability(payload)
                    f.write(f"Category: {vulnerability_category}\n\n")

            colored_logging(f"[i] Detailed report saved to {report_filename}", "info")

        def assess_risk(payload):
            if "{{7*7}}" in payload:
                return "High - Code Execution"
            elif "{{" in payload:
                return "Medium - Template Injection"
            else:
                return "Low - Potential Misconfiguration"

        def suggest_remediation(payload):
            if "{{7*7}}" in payload:
                return "Ensure proper output encoding and avoid rendering untrusted input in templates."
            elif "{{" in payload:
                return "Limit template engine exposure and use strict sandboxing."
            return "Review template rendering mechanism for potential weaknesses."

        def categorize_vulnerability(payload):
            if "{{7*7}}" in payload:
                return "SSTI - Code Execution"
            elif "{{" in payload:
                return "SSTI - Template Injection"
            return "Unknown - Review needed"

        def main():
            os.system('cls' if os.name == 'nt' else 'clear')

            title = """
            ███████╗███████╗███████╗███████╗
            ██╔════╝██╔════╝██╔════╝██╔════╝
            ███████╗███████╗███████╗███████╗
            ╚════██║╚════██║╚════██║╚════██║
            ███████║███████║███████║███████║
            ╚══════╝╚══════╝╚══════╝╚══════╝
            """
            print(Fore.MAGENTA + title)
            print(Fore.YELLOW + "Welcome to the Genesis SSTI Scanner")
            
            target_url = input(Fore.CYAN + "[?] Enter the target URL: ").strip()
            user_agents = load_user_agents()

            print(Fore.CYAN + "[?] Select scanning mode:")
            print(Fore.CYAN + "[1] Asynchronous SSTI Scan")
            print(Fore.CYAN + "[2] Threaded SSTI Scan")
            scan_mode = input(Fore.CYAN + "Enter your choice (1 or 2, press Enter for 1): ").strip() or "1"

            detect_engine_choice = input(Fore.CYAN + "[?] Attempt dynamic template engine detection? (y/n): ").strip().lower()
            engine = None
            if detect_engine_choice == 'y':
                engine = detect_template_engine_dynamic(target_url, user_agents)

            payloads = prompt_for_payloads(engine)

            if scan_mode == "1":
                asyncio.run(check_ssti_async(target_url, payloads, user_agents))
            else:
                max_threads = int(input(Fore.CYAN + "[?] Enter the number of threads to use (default 5): ").strip() or "5")
                total_found, vulnerable_payloads, vulnerable_urls = check_ssti(target_url, payloads, max_threads, user_agents)
                save_results_to_file(vulnerable_payloads, vulnerable_urls)
                generate_detailed_report(vulnerable_payloads, vulnerable_urls)

        if __name__ == "__main__":
            main()

    def run_xxe_scanner():
        logging.basicConfig(
            filename='xxe_scanner.log',
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=logging.INFO
        )

        init(autoreset=True) 

        def colored_logging(message, level='info'):
            if level == 'critical':
                print(Fore.RED + message)
                logging.critical(message)
            elif level == 'warning':
                print(Fore.YELLOW + message)
                logging.warning(message)
            else:
                print(Fore.CYAN + message)
                logging.info(message)

        def load_user_agents(yaml_file='config.yaml'):
            try:
                with open(yaml_file, 'r') as file:
                    data = yaml.safe_load(file)
                    return data.get('user_agents', [])
            except FileNotFoundError:
                colored_logging(f"[!] YAML file not found: {yaml_file}", "critical")
                sys.exit(1)
            except yaml.YAMLError as e:
                colored_logging(f"[!] Error parsing YAML file: {e}", "critical")
                sys.exit(1)

        def load_xxe_signatures(yaml_file='xxe_signatures.yaml'):
            try:
                with open(yaml_file, 'r') as file:
                    data = yaml.safe_load(file)
                    return data.get('xxe_signatures', [])
            except FileNotFoundError:
                colored_logging(f"[!] YAML file not found: {yaml_file}", "critical")
                sys.exit(1)
            except yaml.YAMLError as e:
                colored_logging(f"[!] Error parsing YAML file: {e}", "critical")
                sys.exit(1)

        def perform_request(url, user_agents, payload, session_cookies=None, auth_token=None):
            headers = {'User-Agent': random.choice(user_agents), 'Content-Type': 'application/xml'}
            cookies = session_cookies if session_cookies else {}

            if auth_token:
                headers['Authorization'] = f"Bearer {auth_token}"

            try:
                encoded_payload = payload.encode('utf-8')

                response = requests.post(url, data=encoded_payload, headers=headers, cookies=cookies, timeout=10)
                return response
            except requests.Timeout:
                colored_logging(f"[!] Timeout error: {url}", "warning")
                return None
            except requests.RequestException as e:
                colored_logging(f"[!] Request error: {e}", "critical")
                return None

        def analyze_response(response, signatures):
            try:
                for signature in signatures:
                    pattern = signature['pattern']
                    severity = signature['severity']
                    description = signature['description']

                    if re.search(pattern, response.text, re.IGNORECASE):
                        return 1, severity, pattern, description

                return 0, None, None, None
            except requests.RequestException as e:
                print(f"Request error: {e}")
                return "Error", None, None, None

        def categorize_vulnerability(payload):
            if "DOCTYPE" in payload or "ENTITY" in payload:
                return "Critical", "XXE Injection attempt detected. Consider disabling DTD processing or using XML libraries that don't support external entities."
            elif "file:///" in payload:
                return "High", "Possible file inclusion vulnerability. Ensure the application doesn't accept or process untrusted XML inputs."
            else:
                return "Low", "Potential XML error. Review the XML parsing code and validate inputs."

        def generate_report(vulnerable_payloads, vulnerable_urls, vulnerabilities):
            report = []
            for i, (url, severity, signature, payload_severity, remediation) in enumerate(vulnerabilities):
                report.append(f"Vulnerability {i+1}:\n"
                            f"Payload: {vulnerable_payloads[i]}\n"
                            f"URL: {url}\n"
                            f"Signature: {signature}\n"
                            f"Severity: {payload_severity}\n"
                            f"Remediation: {remediation}\n")

            return "\n".join(report)

        def save_results_to_file(vulnerable_payloads, vulnerable_urls, report, output_format="txt"):
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = f"xxe_scan_results_{timestamp}.{output_format}"

            if output_format == "txt":
                with open(filename, 'w') as f:
                    f.write("Vulnerable Payloads:\n")
                    f.write('\n'.join(vulnerable_payloads))
                    f.write("\n\nVulnerable URLs:\n")
                    f.write('\n'.join(vulnerable_urls))
                    f.write("\n\nDetailed Report:\n")
                    f.write(report)
            elif output_format == "json":
                data = {
                    "vulnerable_payloads": vulnerable_payloads,
                    "vulnerable_urls": vulnerable_urls,
                    "report": report
                }
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=4)

            colored_logging(f"[i] Results saved to {filename}", "info")

        def check_xxe(target_url, payloads, max_threads, user_agents, signatures):
            print(f"{Fore.CYAN}[i] Starting XXE scan on: {target_url}")
            total_found = 0
            vulnerable_payloads = []
            vulnerable_urls = []
            vulnerabilities = []

            def test_payload(payload, signatures):
                response = perform_request(target_url, user_agents, payload)

                if response:
                    is_vulnerable, severity, pattern, description = analyze_response(response, signatures)
                    
                    if is_vulnerable:
                        payload_severity, remediation = categorize_vulnerability(payload)
                        print(f"{Fore.GREEN}[+] Vulnerable with payload: {payload}")
                        print(f"{Fore.YELLOW}[!] Vulnerability: {pattern} (Severity: {payload_severity})")
                        print(f"{Fore.RED}[!] Remediation: {remediation}")
                        return payload, target_url, severity, pattern, payload_severity, remediation
                    
                    print(f"{Fore.YELLOW}[-] Not Vulnerable: {target_url}")
                    return None, None, None, None, None, None

                return None, None, None, None, None, None

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = [
                    executor.submit(test_payload, payload, signatures) 
                    for payload in payloads
                ]

                for future in concurrent.futures.as_completed(futures):
                    try:
                        result, url, severity, signature, payload_severity, remediation = future.result()
                        if result:
                            total_found += 1
                            vulnerable_payloads.append(result)
                            vulnerable_urls.append(url)
                            vulnerabilities.append({
                                "severity": severity,
                                "signature": signature,
                                "payload_severity": payload_severity,
                                "remediation": remediation
                            })
                    except Exception as e:
                        print(f"Error in test_payload: {e}")

            return total_found, vulnerable_payloads, vulnerable_urls, vulnerabilities

        def prompt_for_payloads():
            payloads = []
            print(Fore.CYAN + "[?] Load payloads from a file or enter manually?")
            print(Fore.CYAN + "[1] Load from a file")
            print(Fore.CYAN + "[2] Enter manually")

            payload_choice = input(Fore.CYAN + "Enter your choice (1 or 2, press Enter for 1): ").strip()
            if payload_choice == '2':
                print(Fore.CYAN + "[i] Enter your payloads, one per line. Enter 'done' to finish:")
                while True:
                    payload = input("Payload: ").strip()
                    if payload.lower() == 'done':
                        break
                    payloads.append(payload)
            else:
                file_path = input(Fore.CYAN + "Enter the file path for payloads: ").strip()
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        payloads = [line.strip() for line in f.readlines()]
                else:
                    print(Fore.RED + f"[!] File not found: {file_path}")
                    sys.exit(1)

            return payloads

        def main():
            os.system('cls' if os.name == 'nt' else 'clear')

            title = """
            ██╗  ██╗██╗  ██╗███████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ███╗███████╗██████╗ 
            ██║ ██╔╝██║  ██║██╔════╝     ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗ ████║██╔════╝██╔══██╗
            █████╔╝ ███████║█████╗       ███████╗██║     ███████║██╔██╗ ██║██╔████╔██║█████╗  ██████╔╝
            ██╔═██╗ ██╔══██║██╔══╝       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╔╝██║██╔══╝  ██╔══██╗
            ██║  ██╗██║  ██║███████╗     ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚═╝ ██║███████╗██║  ██║
            ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝
            """
            print(Fore.GREEN + title)

            target_url = input(Fore.CYAN + "[?] Enter the target URL: ").strip()

            max_threads = int(input(Fore.CYAN + "[?] Enter maximum number of threads (default: 5): ").strip() or 5)

            user_agents = load_user_agents()

            payloads = prompt_for_payloads()

            signatures = load_xxe_signatures()

            total_found, vulnerable_payloads, vulnerable_urls, vulnerabilities = check_xxe(target_url, payloads, max_threads, user_agents, signatures)

            if total_found == 0:
                print(f"{Fore.GREEN}[i] No vulnerabilities found in {target_url}")
                logging.info(f"No vulnerabilities found in {target_url}")
            else:
                report = generate_report(vulnerable_payloads, vulnerable_urls, vulnerabilities)
                save_results_to_file(vulnerable_payloads, vulnerable_urls, report)

        if __name__ == "__main__":
            main()
   
    def run_os_injection_scanner():
        logging.basicConfig(
            filename='os_injection_scanner.log',
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=logging.INFO
        )

        init(autoreset=True)

        def colored_logging(message, level='info'):
            if level == 'critical':
                print(Fore.RED + message)
                logging.critical(message)
            elif level == 'warning':
                print(Fore.YELLOW + message)
                logging.warning(message)
            else:
                print(Fore.CYAN + message)
                logging.info(message)

        def load_user_agents(yaml_file='config.yaml'):
            try:
                with open(yaml_file, 'r') as file:
                    data = yaml.safe_load(file)
                    return data.get('user_agents', [])
            except FileNotFoundError:
                colored_logging(f"[!] YAML file not found: {yaml_file}", "critical")
                sys.exit(1)
            except yaml.YAMLError as e:
                colored_logging(f"[!] Error parsing YAML file: {e}", "critical")
                sys.exit(1)

        def load_error_signatures(yaml_file='os_error_signatures.yaml'):
            try:
                with open(yaml_file, 'r') as file:
                    data = yaml.safe_load(file)
                    return data.get('error_signatures', {})
            except FileNotFoundError:
                colored_logging(f"[!] YAML file not found: {yaml_file}", "critical")
                sys.exit(1)
            except yaml.YAMLError as e:
                colored_logging(f"[!] Error parsing YAML file: {e}", "critical")
                sys.exit(1)

        def perform_request(url, user_agents, session_cookies=None, auth_token=None):
            headers = {'User-Agent': random.choice(user_agents)}
            cookies = session_cookies if session_cookies else {}
            
            if auth_token:
                headers['Authorization'] = f"Bearer {auth_token}"

            try:
                response = requests.get(url, headers=headers, cookies=cookies, timeout=10)
                log_response_details(response, None)
                return response
            except requests.Timeout:
                colored_logging(f"[!] Timeout error: {url}", "warning")
                return None
            except requests.RequestException as e:
                colored_logging(f"[!] Request error: {e}", "critical")
                return None

        def randomize_payload(payload):
            random_comments = ['<!--random-->', '{#comment#}', '{/*comment*/}', '#random']
            components = payload.split(';')
            random_comments_inserted = [components[0]] + [
                f";{random.choice(random_comments)} {comp}" for comp in components[1:]
            ]
            return ''.join(random_comments_inserted)

        def adjust_payloads_for_os(payload, target_os):
            if target_os == 'windows':
                return payload.replace(';', '&&').replace('/', '\\')
            elif target_os == 'linux':
                return payload
            else:
                colored_logging("[!] Unknown OS, using default payload", "warning")
                return payload

        def evade_waf_and_ids(payload):
            evasion_techniques = [
                lambda p: urllib.parse.quote(p),  # URL Encoding
                lambda p: p.replace(";", " ; "),  # Space Insertion
                lambda p: p.lower(),  # Case Alteration
            ]

            evaded_payloads = [technique(payload) for technique in evasion_techniques]
            return evaded_payloads

        def log_response_details(response, payload):
            logging.info(f"Request to {response.url} returned status {response.status_code}")
            logging.info(f"Payload: {payload}")
            logging.info(f"Response Headers: {response.headers}")
            logging.info(f"Response Content Length: {len(response.text)}")
            
        def get_valid_integer_input(prompt):
            while True:
                user_input = input(prompt).strip()
                if user_input.isdigit():
                    return int(user_input)
                else:
                    print(Fore.RED + "[!] Invalid input. Please enter a valid number.")

        def analyze_response(response, payload, baseline_length, error_signatures):
            detected_os = None
            for os_type, signatures in error_signatures.items():
                for signature in signatures:
                    if re.search(signature, response.text, re.IGNORECASE):
                        colored_logging(f"[+] Detected OS: {os_type} (matched signature: {signature})", "info")
                        detected_os = os_type
                        break
                if detected_os:
                    break

            if detected_os:
                os_adjusted_payload = adjust_payloads_for_os(payload, detected_os)
                return True, os_adjusted_payload

            if abs(len(response.text) - baseline_length) > 100:
                return True, payload
            if response.status_code in [500, 502, 503, 504]:
                return True, payload

            return False, None

        def check_os_injection(target_url, payloads, max_threads, user_agents, error_signatures):
            print(f"{Fore.CYAN}[i] Starting OS command injection scan on: {target_url}")
            total_found = 0
            vulnerable_payloads = []
            vulnerable_urls = []

            baseline_response = perform_request(target_url, user_agents)
            baseline_length = len(baseline_response.text) if baseline_response else 0

            def test_payload(payload):
                randomized_payload = randomize_payload(payload)
                for evasion_payload in evade_waf_and_ids(randomized_payload):
                    url = f"{target_url}/?input={evasion_payload}"
                    response = perform_request(url, user_agents)

                    if response:
                        vulnerable, adjusted_payload = analyze_response(response, evasion_payload, baseline_length, error_signatures)
                        if vulnerable:
                            colored_logging(f"{Fore.GREEN}[+] Vulnerable with payload: {adjusted_payload}", "info")
                            return adjusted_payload, url

                colored_logging(f"{Fore.YELLOW}[-] Not Vulnerable: {url}", "warning")
                return None, None

            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = {executor.submit(test_payload, payload): payload for payload in payloads}
                for future in as_completed(futures):
                    result, url = future.result()
                    if result and url:
                        total_found += 1
                        vulnerable_payloads.append(result)
                        vulnerable_urls.append(url)

            return total_found, vulnerable_payloads, vulnerable_urls

        def save_results_to_file(vulnerable_payloads, vulnerable_urls):
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = f"os_injection_results_{timestamp}.txt"
            with open(filename, 'w') as f:
                f.write("Vulnerable Payloads:\n")
                f.write('\n'.join(vulnerable_payloads))
                f.write("\n\nVulnerable URLs:\n")
                f.write('\n'.join(vulnerable_urls))
            colored_logging(f"[i] Results saved to {filename}", "info")

        def generate_detailed_report(vulnerable_payloads, vulnerable_urls):
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            report_filename = f"os_detailed_report_{timestamp}.txt"

            with open(report_filename, 'w') as f:
                f.write("=== OS Injection Detailed Vulnerability Report ===\n")
                f.write(f"Scan conducted on: {timestamp}\n\n")

                for i, (payload, url) in enumerate(zip(vulnerable_payloads, vulnerable_urls)):
                    f.write(f"Vulnerability {i+1}:\n")
                    f.write(f"URL: {url}\n")
                    f.write(f"Payload: {payload}\n")
                    
                    risk_level = assess_risk(payload)
                    f.write(f"Risk Level: {risk_level}\n")
                    
                    remediation_steps = suggest_remediation(payload)
                    f.write(f"Remediation: {remediation_steps}\n\n")
                    
                    vulnerability_category = categorize_vulnerability(payload)
                    f.write(f"Category: {vulnerability_category}\n\n")

            colored_logging(f"[i] Detailed report saved to {report_filename}", "info")

        def assess_risk(payload):
            if "; whoami" in payload:
                return "High - Code Execution"
            elif ";" in payload:
                return "Medium - Command Injection"
            else:
                return "Low - Potential Misconfiguration"

        def suggest_remediation(payload):
            if "; whoami" in payload:
                return "Sanitize input and avoid passing unsanitized data to shell commands."
            elif ";" in payload:
                return "Implement strict input validation and use prepared statements."
            return "Review input handling mechanisms."

        def categorize_vulnerability(payload):
            if "; whoami" in payload:
                return "OS Command Injection - Code Execution"
            elif ";" in payload:
                return "OS Command Injection"
            return "Unknown - Review needed"

        def prompt_for_payloads():
            payloads = []
            print(Fore.CYAN + "[?] Load payloads from a file or enter manually?")
            print(Fore.CYAN + "[1] Load from a file")
            print(Fore.CYAN + "[2] Enter manually")

            payload_choice = input(Fore.CYAN + "Enter your choice (1 or 2, press Enter for 1): ").strip()
            if payload_choice == '2':
                print(Fore.CYAN + "[i] Enter your payloads, one per line. Enter 'done' to finish:")
                while True:
                    payload = input("Payload: ").strip()
                    if payload.lower() == 'done':
                        break
                    payloads.append(payload)
            else:
                file_path = input(Fore.CYAN + "Enter the file path for payloads: ").strip()
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        payloads = [line.strip() for line in f.readlines()]
                else:
                    print(Fore.RED + f"[!] File not found: {file_path}")
                    sys.exit(1)

            return payloads

        def main():
            os.system('cls' if os.name == 'nt' else 'clear')

            title = """
            ██████╗  ██████╗     ██╗███████╗██╗███████╗████████╗██╗ ██████╗ 
            ██╔══██╗██╔═══██╗    ██║██╔════╝██║██╔════╝╚══██╔══╝██║██╔═══██╗
            ██║  ██║██║   ██║    ██║█████╗  ██║███████╗   ██║   ██║██║   ██║
            ██║  ██║██║   ██║    ██║██╔══╝  ██║╚════██║   ██║   ██║██║   ██║
            ██████╔╝╚██████╔╝    ██║██║     ██║███████║   ██║   ██║╚██████╔╝
            ╚═════╝  ╚═════╝     ╚═╝╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝ ╚═════╝ 
            """
            print(Fore.RED + title)
            print(Fore.YELLOW + "Welcome to the Genesis OS Injection Scanner")
            
            user_agents = load_user_agents()
            error_signatures = load_error_signatures()

            target_url = input(Fore.CYAN + "[?] Enter the target URL: ").strip()
            max_threads = get_valid_integer_input(Fore.CYAN + "[?] Enter the number of threads to use: ")
            payloads = prompt_for_payloads()

            total_found, vulnerable_payloads, vulnerable_urls = check_os_injection(target_url, payloads, max_threads, user_agents, error_signatures)

            if total_found > 0:
                save_results_to_file(vulnerable_payloads, vulnerable_urls)
                generate_detailed_report(vulnerable_payloads, vulnerable_urls)
            else:
                colored_logging(f"[i] No OS injection vulnerabilities found.", "info")

        if __name__ == "__main__":
            main()

                
    def handle_selection(selection):
        if selection == '1':
            clear_screen()
            run_lfi_scanner()

        elif selection == '2':
            clear_screen()
            run_or_scanner()

        elif selection == '3':
            clear_screen()
            run_sql_scanner()

        elif selection == '4':
            clear_screen()
            run_xss_scanner()
        elif selection == '5':
            clear_screen()
            run_ssrf_scanner()
        elif selection == '6':
            clear_screen()
            run_ssti_scanner()
        elif selection == '7':
            run_xxe_scanner()
        elif selection == '8':
            run_os_injection_scanner()
        elif selection == '9':
            print_exit_menu()

        else:
            print_exit_menu()

    def main():
        clear_screen()
        required_packages = {
            'aiohttp': '3.8.6',
            'requests': '2.28.1',
            'prompt_toolkit': '3.0.36',
            'colorama': '0.4.6'
        }

        check_and_install_packages(required_packages)

        sleep(3)
        clear_screen()

        while True:
            display_menu()
            choice = input(f"\n{Fore.CYAN}[?] Select an option (0-9): {Style.RESET_ALL}").strip()
            handle_selection(choice)

    if __name__ == "__main__":
        try:
            main()
        except KeyboardInterrupt:
            print_exit_menu()
            sys.exit(0)

except KeyboardInterrupt:
    print_exit_menu()
    sys.exit(0)