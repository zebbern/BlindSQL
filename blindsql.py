import os
import time
import concurrent.futures
import random
import logging
import argparse
import threading
import requests
from urllib.parse import quote

from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn

# Setup a basic logger (Rich handles most UI output)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
console = Console()

class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

class BSS:
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.2 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.70",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
    ]

    def __init__(self):
        self.vulnerabilities_found = 0
        self.total_tests = 0
        self.verbose = False
        # Group results by base URL.
        # Each key is a base URL and the value is a list of tuples:
        # (payload, response_time, threshold, status_code)
        self.vulnerability_results = {}
        self.results_lock = threading.Lock()  # Ensure thread-safe updates
        self.proxies = None
        self.request_timeout = 15  # Seconds timeout per request
        self.threshold_multiplier = 3  # Automatic threshold = baseline * multiplier
        self.baselines = {}  # Cache baseline response times per URL
        self.session = requests.Session()  # Reuse HTTP connections

    def get_random_user_agent(self):
        return random.choice(self.USER_AGENTS)

    def set_proxy(self, proxy):
        self.proxies = {'http': proxy, 'https': proxy}

    def perform_request(self, url, payload, cookie):
        """
        Perform a GET request on the base URL with the given payload appended.
        Returns (success, full_url, response_time, status_code, error_message)
        """
        url_with_payload = f"{url}{payload}"
        start_time = time.time()
        headers = {'User-Agent': self.get_random_user_agent()}
        try:
            response = self.session.get(
                url_with_payload,
                headers=headers,
                cookies={'cookie': cookie} if cookie else None,
                proxies=self.proxies,
                timeout=self.request_timeout
            )
            response.raise_for_status()
            response_time = time.time() - start_time
            return True, url_with_payload, response_time, response.status_code, None
        except requests.exceptions.RequestException as e:
            response_time = time.time() - start_time
            return False, url_with_payload, response_time, None, str(e)

    def get_baseline(self, url, cookie, attempts=3):
        """
        Measure and cache the baseline response time for a URL.
        (Baseline logging messages have been removed for cleaner output.)
        """
        if url in self.baselines:
            return self.baselines[url]
        times = []
        headers = {'User-Agent': self.get_random_user_agent()}
        for _ in range(attempts):
            try:
                start = time.time()
                response = self.session.get(
                    url,
                    headers=headers,
                    cookies={'cookie': cookie} if cookie else None,
                    proxies=self.proxies,
                    timeout=self.request_timeout
                )
                response.raise_for_status()
                times.append(time.time() - start)
            except requests.exceptions.RequestException as e:
                logger.warning(f"{Color.YELLOW}Baseline error for {url}: {e}{Color.RESET}")
        baseline = sum(times) / len(times) if times else 0.5
        self.baselines[url] = baseline
        return baseline

    def read_file(self, path):
        try:
            with open(path, 'r', encoding='utf-8') as file:
                return [line.strip() for line in file if line.strip()]
        except Exception as e:
            logger.error(f"{Color.RED}Error reading file {path}: {e}{Color.RESET}")
            return []

    def save_vulnerable_urls(self, filename):
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                for url, vulnerabilities in self.vulnerability_results.items():
                    for vuln in vulnerabilities:
                        payload, response_time, threshold, status_code = vuln
                        file.write(f"{url} + {payload}\n")
            logger.info(f"{Color.GREEN}Vulnerable URLs saved to {filename}{Color.RESET}")
        except Exception as e:
            logger.error(f"{Color.RED}Error saving URLs: {e}{Color.RESET}")

    def process_test(self, url, payload, cookie):
        """
        Process one test: measure the baseline, perform the request,
        and if the response time exceeds (baseline * multiplier),
        record the vulnerability with the payload only.
        """
        baseline = self.get_baseline(url, cookie)
        threshold = baseline * self.threshold_multiplier

        success, url_with_payload, response_time, status_code, error_message = self.perform_request(url, payload, cookie)
        with self.results_lock:
            self.total_tests += 1

        if success and status_code and response_time >= threshold:
            with self.results_lock:
                self.vulnerabilities_found += 1
                if url not in self.vulnerability_results:
                    self.vulnerability_results[url] = []
                self.vulnerability_results[url].append((payload, response_time, threshold, status_code))
            if self.verbose:
                logger.info(f"{Color.GREEN}Vulnerable: {url} | Payload: {payload} | {response_time:.2f}s (Threshold: {threshold:.2f}s) | Status: {status_code}{Color.RESET}")
        elif self.verbose:
            logger.info(f"{Color.RED}Not Vulnerable: {url} | Payload: {payload} | {response_time:.2f}s (Threshold: {threshold:.2f}s) | Status: {status_code}{Color.RESET}")

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def display_banner(self):
        print(Color.GREEN + r""" ___ _    ___ _  _ ___    ___  ___  _    
| _ ) |  |_ _| \| |   \  / __|/ _ \| |   
| _ \ |__ | || .` | |) | \__ \ (_) | |__ 
|___/____|___|_|\_|___/  |___/\__\_\____|
------------------------------------------
Created by: github.com/zebbern
 """ + Color.RESET)

    def parse_args(self):
        parser = argparse.ArgumentParser(
            description="Blind SQL Scanner"
        )
        parser.add_argument('-u', '--url', help="URL or path to URL list file", default=None)
        parser.add_argument('-p', '--payload', help="Path to payload file", default=None)
        parser.add_argument('-c', '--cookie', help="Cookie for GET requests", default="")
        parser.add_argument('--proxy', help="Proxy address (e.g., http://127.0.0.1:8080)", default=None)
        parser.add_argument('-t', '--threads', help="Number of threads (0 for sequential)", type=int, default=0)
        parser.add_argument('-v', '--verbose', help="Enable verbose mode", action='store_true')
        parser.add_argument('-o', '--output', help="Filename to save vulnerable URLs", default=None)
        return parser.parse_args()

    def build_renderable(self, total_tests, progress):
        """
        Build a renderable Group containing the grouped vulnerability panels (one per base URL)
        and the progress bar (which now shows the count of tests, e.g. "5/41 tests").
        """
        group_items = []

        # Build a panel for each base URL with its vulnerabilities.
        with self.results_lock:
            for base_url, vulnerabilities in self.vulnerability_results.items():
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Payload", style="cyan", overflow="fold")
                table.add_column("Response Time (s)", justify="center", style="green")
                table.add_column("Threshold (s)", justify="center", style="red")
                table.add_column("Status Code", justify="center", style="blue")
                for idx, (payload, response_time, threshold, status_code) in enumerate(vulnerabilities):
                    # Create a clickable hyperlink with URL‑encoding to handle spaces and special characters
                    full_url = base_url + quote(payload, safe="")
                    link_markup = f"[link={full_url}]{payload}[/link]"
                    table.add_row(link_markup, f"{response_time:.2f}", f"{threshold:.2f}", str(status_code))
                    if idx < len(vulnerabilities) - 1:
                        table.add_section()  # Separator line between results
                panel = Panel(table, title=f"[bold blue]{base_url}[/]", border_style="blue")
                group_items.append(panel)

        # Append the progress bar at the bottom.
        group_items.append(progress)
        return Group(*group_items)

    def main(self):
        # Clear screen and display banner for inputs.
        self.clear_screen()
        self.display_banner()

        args = self.parse_args()

        # Get URL(s)
        if args.url:
            input_url_or_file = args.url
        else:
            input_url_or_file = console.input("[bold blue]Enter the URL or path to the URL list file: [/]")
        if not input_url_or_file:
            logger.error(f"{Color.RED}No URL or URL list file provided.{Color.RESET}")
            return

        urls = [input_url_or_file] if not os.path.isfile(input_url_or_file) else self.read_file(input_url_or_file)
        if not urls:
            logger.error(f"{Color.RED}No valid URLs provided.{Color.RESET}")
            return

        # Get payload file:
        # If a payload file is not provided via CLI, list all .txt files in the "payload" directory and let the user choose one.
        if args.payload:
            payload_path = args.payload
        else:
            payload_dir = "payload"
            if not os.path.isdir(payload_dir):
                logger.error(f"{Color.RED}Payload directory '{payload_dir}' not found.{Color.RESET}")
                return
            files = [f for f in os.listdir(payload_dir) if f.endswith(".txt")]
            if not files:
                logger.error(f"{Color.RED}No payload files found in directory '{payload_dir}'.{Color.RESET}")
                return
            console.print("[bold blue]Available payload files:[/]")
            for idx, f in enumerate(files, start=1):
                console.print(f"[{idx}] {f}")
            choice = console.input("Select payload file by number: ")
            try:
                choice = int(choice)
                if 1 <= choice <= len(files):
                    payload_path = os.path.join(payload_dir, files[choice - 1])
                else:
                    logger.error(f"{Color.RED}Invalid selection.{Color.RESET}")
                    return
            except Exception as e:
                logger.error(f"{Color.RED}Invalid input: {e}{Color.RESET}")
                return

        payloads = self.read_file(payload_path)
        if not payloads:
            logger.error(f"{Color.RED}No valid payloads found in file: {payload_path}{Color.RESET}")
            return

        cookie = args.cookie if args.cookie else console.input("[bold blue]Enter the cookie (leave empty if none): [/]")
        if args.proxy:
            self.set_proxy(args.proxy)
        elif not args.url:
            proxy_input = console.input("[bold blue]Enter proxy address (or leave empty): [/]")
            if proxy_input:
                self.set_proxy(proxy_input)

        self.verbose = args.verbose

        try:
            threads = args.threads
        except ValueError:
            logger.error(f"{Color.RED}Invalid thread count. Using sequential execution.{Color.RESET}")
            threads = 0

        tests = [(url, payload) for url in urls for payload in payloads]
        total_tests = len(tests)

        # Clear the screen once all inputs are collected so only the live UI is visible.
        self.clear_screen()

        # Setup Rich progress bar with an extra column showing "X/Y tests".
        progress = Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total} tests"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        )
        task_id = progress.add_task("Scanning...", total=total_tests)

        start_scan = time.time()
        try:
            with Live(self.build_renderable(total_tests, progress), refresh_per_second=10, console=console) as live:
                if threads == 0:
                    # Sequential execution
                    for url, payload in tests:
                        self.process_test(url, payload, cookie)
                        progress.advance(task_id, 1)
                        live.update(self.build_renderable(total_tests, progress))
                else:
                    # Concurrent execution
                    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                        futures = [executor.submit(self.process_test, url, payload, cookie) for url, payload in tests]
                        for future in concurrent.futures.as_completed(futures):
                            try:
                                future.result()
                            except Exception as e:
                                logger.warning(f"{Color.YELLOW}Exception in thread: {e}{Color.RESET}")
                            progress.advance(task_id, 1)
                            live.update(self.build_renderable(total_tests, progress))
        except KeyboardInterrupt:
            console.print("\n[bold red]Scan cancelled by user![/]")
        total_time = time.time() - start_scan

        console.print(f"\n[bold blue]Scan Complete.[/]")
        console.print(f"[yellow]Total Tests: {self.total_tests}[/]")
        console.print(f"[green]Vulnerabilities Found: {self.vulnerabilities_found}[/]")
        console.print(f"[cyan]Total Scan Time: {total_time:.2f} seconds[/]\n")

        output_file = args.output if args.output else console.input("[bold blue]Enter filename to save results (leave empty to skip): [/]")
        if output_file:
            self.save_vulnerable_urls(output_file)

        console.print("[bold blue]Thank you for using Blind SQL Scanner by zebbern![/]")

if __name__ == "__main__":
    scanner = BSS()
    scanner.main()
