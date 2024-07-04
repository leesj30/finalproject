import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 방문한 URL을 저장하는 집합과 공격 벡터를 저장하는 리스트
visited_urls = set()
attack_vectors = []

# 웹 크롤러 함수
def crawl(url, base_url, depth=3):
    # 깊이가 0이거나 이미 방문한 URL이거나 기본 URL로 시작하지 않는 경우 반환
    if depth == 0 or url in visited_urls or not url.startswith(base_url):
        return
    visited_urls.add(url)
    
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Error during request to {url}: {e}")
        return

    # HTML 파싱
    soup = BeautifulSoup(response.text, 'html.parser')

    # 모든 폼 요소 수집
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        form_url = urljoin(base_url, action)
        if check_url_existence(form_url):
            attack_vectors.append((form_url, method, inputs))

    # 모든 링크 요소 수집 및 재귀적 크롤링
    links = soup.find_all('a', href=True)
    for link in links:
        href = link.get('href')
        next_url = urljoin(base_url, href)
        if check_url_existence(next_url):  # 링크 유효성 검사 추가
            crawl(next_url, base_url, depth - 1)

    # URL 매개변수 공격 벡터 추가
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    if query_params:
        attack_vectors.append((url, 'get', query_params))

# SQL 인젝션 탐지 함수
def check_sql_injection(url, method, inputs):
    # SQL 인젝션 페이로드와 에러 패턴 정의
    error_payloads = ["'", '"', ";", "--", "/*", "*/", "#"]
    boolean_true_payloads = ["1=1", "' OR '1'='1", "\" OR \"1\"=\"1"]
    boolean_false_payloads = ["1=2", "' AND '1'='2", "\" AND \"1\"=\"2"]
    union_payloads = ["UNION SELECT NULL", "UNION SELECT NULL, NULL", "UNION SELECT NULL, NULL, NULL"]
    error_patterns = ["syntax error", "unexpected", "error in your SQL syntax"]
    union_error_patterns = ["column", "syntax error", "number of columns"]

    # 페이로드 그룹 정의
    payloads = [
        (error_payloads, error_patterns),
        (boolean_true_payloads, [""]),
        (boolean_false_payloads, [""]),
        (union_payloads, union_error_patterns)
    ]

    # 각 페이로드 그룹에 대해 SQL 인젝션 검사
    for payload_group, patterns in payloads:
        for payload in payload_group:
            response = send_payload(url, method, inputs, payload)
            if response and any(pattern in response.text.lower() for pattern in patterns):
                logger.info(f"SQL Injection vulnerability detected at {url} with payload: {payload}")
                return True
    return False

# 페이로드 전송 함수
def send_payload(url, method, inputs, payload):
    if isinstance(inputs, dict):  # URL 매개변수인 경우
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        for key in query_params:
            query_params[key] = payload
        encoded_query = urlencode(query_params, doseq=True)
        attack_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{encoded_query}"
    else:  # 폼 입력 필드인 경우
        data = {inp.get('name'): payload for inp in inputs if inp.get('name')}
        if method == 'post':
            if not check_url_existence(url):
                return None
            try:
                response = requests.post(url, data=data)
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
        response = requests.get(attack_url)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        logger.error(f"Error during request to {attack_url}: {e}")
        return None

# URL 존재 여부 확인 함수
def check_url_existence(url):
    try:
        response = requests.head(url, allow_redirects=True)
        return response.status_code == 200
    except requests.RequestException as e:
        logger.error(f"Error checking URL existence: {url}, {e}")
        return False

# 민감 정보 노출 탐지 함수
def check_information_disclosure(url):
    sensitive_files = [".env", ".git", ".DS_Store", "config.php"]
    vulnerable = False

    for file in sensitive_files:
        response = requests.get(urljoin(url, file))
        if response.status_code == 200:
            logger.info(f"Sensitive file exposed: {file}")
            vulnerable = True
    return vulnerable

# 약한 비밀번호 강도 탐지 함수
def check_weak_password_strength(password):
    if (len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[!@#\$%\^&\*\(\)_\+\-=\[\]\{\};:'\"\\|,.<>\/?]", password)):
        return False
    return True

# 위치 노출 탐지 함수
def check_location_exposure(url):
    response = requests.get(url)
    ip_headers = ["X-Forwarded-For", "X-Real-IP", "Client-IP"]
    gps_keywords = ["navigator.geolocation.getCurrentPosition"]

    for header in ip_headers:
        if header in response.headers:
            logger.info(f"Potential IP address exposure in header: {header} = {response.headers[header]}")
            return True
    
    if any(keyword in response.text for keyword in gps_keywords):
        logger.info(f"Potential GPS data exposure found in response.")
        return True

    return False

# 종합 보안 검사 함수
def run_security_checks(base_url):
    # 웹 사이트 크롤링 및 공격 벡터 수집
    crawl(base_url, base_url)

    # 각 공격 벡터에 대해 SQL 인젝션 검사
    for url, method, inputs in attack_vectors:
        if check_sql_injection(url, method, inputs):
            logger.info(f"SQL Injection vulnerability detected at {url}")
        else:
            logger.info(f"No SQL Injection vulnerability detected at {url}")
    
    # 민감 정보 노출 검사
    if check_information_disclosure(base_url):
        logger.info("Information Disclosure vulnerability detected.")
    else:
        logger.info("No Information Disclosure vulnerability detected.")

    # 약한 비밀번호 강도 검사
    passwords = ["password", "P@ssw0rd", "12345678", "admin123"]
    for pwd in passwords:
        if check_weak_password_strength(pwd):
            logger.info(f"Weak password detected: {pwd}")
        else:
            logger.info(f"Strong password: {pwd}")

    # 위치 노출 검사
    if check_location_exposure(base_url):
        logger.info("Location Exposure vulnerability detected.")
    else:
        logger.info("No Location Exposure vulnerability detected.")

# 예제 실행
base_url = "http://192.168.219.108"
run_security_checks(base_url)
