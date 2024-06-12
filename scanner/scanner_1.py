import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# 크롤링 함수 (재귀적 크롤링)
def crawl(url, visited):
    urls = set()#크롤링을 시작할 url
    forms = []# 이미 방문한 url을 저장하는 집합(중복방문 피하기용)
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for a_tag in soup.find_all('a', href=True):
            link = urljoin(url, a_tag['href'])
            # 도메인 내의 링크만 추가
            if urlparse(link).netloc == urlparse(url).netloc and link not in visited:
                visited.add(link)
                urls.add(link)
        
        forms.extend(soup.find_all('form'))
    except Exception as e:
        print(f"Error crawling {url}: {e}")
    
    return urls, forms

# 공통 요청 처리 함수
def send_form_request(url, form, payload, method):
    form_action = urljoin(url, form.get('action'))
    method = method.lower()
    inputs = form.find_all('input')
    form_data = {input_tag.get('name'): payload for input_tag in inputs if input_tag.get('name')}
    
    try:
        if method == 'post':
            response = requests.post(form_action, data=form_data)
        else:
            response = requests.get(form_action, params=form_data)
        return response, form_action
    except Exception as e:
        print(f"Error sending request to {form_action}: {e}")
        return None, form_action
    
#--------------------------------------------------------------------------------
# 취약점 탐지 함수
# -------------------------------------------------------------------------------

# 버퍼 오버플로우 탐지 함수
def detect_buffer_overflow(url, forms):
    payload = 'A' * 10000
    for form in forms:
        response, form_action = send_form_request(url, form, payload, form.get('method', 'get'))
        if response and response.status_code != 200:#오류가 나올 때 취약점이 있다고 판단
            print(f"Potential Buffer Overflow at {form_action}")

# 운영체제 명령 실행 취약점 탐지 함수 
def detect_command_injection(url, forms):
    payloads = ["; ls", "&& ls", "| ls", "`ls`"]# 취약점 유발 페이로드
    for form in forms:
        for payload in payloads:
            response, form_action = send_form_request(url, form, payload, form.get('method', 'get'))
            if response and any(term in response.text for term in ["bin", "boot", "dev"]):# bin, boot, dev가 포함되어 있다면 취약점 탐지
                print(f"Potential Command Injection at {form_action}")

# LDAP Injection 탐지 함수 - LDAP 를 사용해야 취약점을 볼 수 있다
def detect_ldap_injection(url, forms):
    payloads = ["*()|&'"]# LDAP Injection 유발할 수 있는 특수 문자 목록 - 추가가능
    for form in forms:
        for payload in payloads:
            response, form_action = send_form_request(url, form, payload, form.get('method', 'get'))
            if response and "LDAP" in response.text:# LDAP라는 리스폰이 오면 취약점 있다고 판단
                print(f"Potential LDAP Injection at {form_action}")

# SQL Injection 취약점 탐지 함수
def detect_sql_injection(url, forms):
    payloads = ["' OR '1'='1", "' OR '1'='2"]# Injection 유발 키워드 - 추가 가능?
    for form in forms:
        for payload in payloads:
            response, form_action = send_form_request(url, form, payload, form.get('method', 'get'))
            if response and any(term in response.text for term in ["SQL", "syntax"]):# SQL 혹은 syntax 구문이 뜨면 취약점
                print(f"Potential SQL Injection at {form_action}")

# XPath Injection 취약점 탐지 함수
def detect_xpath_injection(url, forms):# XML 데이터를 써야 탐지 가능 
    payloads = ["' or '1'='1"]# 취약점 유발 목록
    for form in forms:
        for payload in payloads:
            response, form_action = send_form_request(url, form, payload, form.get('method', 'get'))
            if response and "XPath" in response.text: # XPath 리스폰이면 취약점 탐지
                print(f"Potential XPath Injection at {form_action}")

# 정보 누출 취약점 탐지 함수
def detect_information_disclosure(url, forms):
    # 지금은 완성하기 힘들고 테스트하면서 만져봐야할 것 같습니다
    sensitive_input_value = 'passwd'
    for form in forms:
        response, form_action = send_form_request(url, form, sensitive_input_value, form.get('method', 'get'))

        if response and sensitive_input_value in response.text.lower(): # 중요 정보 키워드 검색
            print(f"Potential Information Disclosure at {form_action}: Found '{sensitive_input_value}' in response")

# 악성 콘텐츠 취약점 탐지 함수
def detect_malicious_content(url, forms):
    # 업로드 시도할 파일 목록 flash, avi, exe
    files_to_upload = {
        'flash': ('test.swf', b'%PDF-1.4 fake flash file content', 'application/x-shockwave-flash'),
        'video': ('test.avi', b'RIFF....AVI fake video file content', 'video/x-msvideo'),
        'executable': ('test.exe', b'MZP fake executable file content', 'application/octet-stream')
    }
    
    for form in forms:
        form_action = urljoin(url, form.get('action'))
        method = form.get('method', 'post').lower()# 파일 업로드는 POST 메소드 사용
        inputs = form.find_all('input')
        
        for file_type, (file_name, file_content, file_mime) in files_to_upload.items():
            form_data = {}
            files = {}
            for input_tag in inputs:
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text').lower()
                if input_name:
                    if input_type == 'file':
                        files[input_name] = (file_name, file_content, file_mime)
                    else:
                        form_data[input_name] = 'test'
            
            try:
                response = requests.post(form_action, data=form_data, files=files)
                if response.status_code == 200 and file_name in response.text:# 파일 업로드가 가능했으면 취약점 탐지
                    print(f"Potential Malicious Content Upload at {form_action}: Uploaded '{file_name}'")
            except Exception as e:
                print(f"Error testing Malicious Content on {form_action}: {e}")

# XSS 공격 취약점 탐지 함수
def detect_xss(url, forms):
    payload = "<script>alert('XSS')</script>" # XSS 공격을 시도하기 위한 페이로드
    for form in forms:
        response, form_action = send_form_request(url, form, payload, form.get('method', 'get'))
        if response and payload in response.text: # 페이로드가 포함되면 취약점 탐지
            print(f"Potential XSS at {form_action}")

# 불충분한 인증 점검
def detect_insufficient_authentication(url, forms):
    payload = 'test'
    for form in forms:
        response, form_action = send_form_request(url, form, payload, form.get('method', 'get'))
        if response and response.status_code == 200 and "login" not in response.url.lower():
            print(f"Potential Insufficient Authentication at {form_action}")

# 취약한 패스워드 복구 점검
def detect_weak_password_recovery(url, forms):
    payload = {'email': 'test@test.com'}
    for form in forms:
        form_action = urljoin(url, form.get('action'))
        method = form.get('method', 'post').lower()
        
        try:
            response = requests.post(form_action, data=payload)
            if response.status_code == 200 and "reset link sent" in response.text.lower():
                print(f"Potential Weak Password Recovery at {form_action}")
        except Exception as e:
            print(f"Error testing Weak Password Recovery on {form_action}: {e}")

# CSRF 점검
def detect_csrf(url, forms):
    payload = 'test'
    for form in forms:
        response, form_action = send_form_request(url, form, payload, form.get('method', 'post'))
        if response and response.status_code == 200 and "csrf" not in response.text.lower():
            print(f"Potential CSRF at {form_action}")

# 불충분한 인가 점검
def detect_insufficient_authorization(url, forms):
    payload = 'test'
    for form in forms:
        response, form_action = send_form_request(url, form, payload, form.get('method', 'get'))
        if response and response.status_code == 200 and "unauthorized" not in response.text.lower():
            print(f"Potential Insufficient Authorization at {form_action}")

# 프로세스 검증 누락 점검
def detect_lack_of_process_validation(url, forms):
    payload = '<script>alert("test")</script>'
    for form in forms:
        response, form_action = send_form_request(url, form, payload, form.get('method', 'post'))
        if response and payload in response.text:
            print(f"Potential Lack of Process Validation at {form_action}")

# 파일 업로드 점검
def detect_file_upload(url, forms):
    files_to_upload = {
        'text': ('test.txt', b'This is a test file.', 'text/plain')
    }
    
    for form in forms:
        for file_type, (file_name, file_content, file_mime) in files_to_upload.items():
            files = {file_type: (file_name, file_content, file_mime)}
            response, form_action = send_form_request(url, form, 'test', form.get('method', 'post'), files)
            if response and response.status_code == 200 and file_name in response.text:
                print(f"Potential File Upload Vulnerability at {form_action}: Uploaded '{file_name}'")

# 파일 다운로드 점검
def detect_file_download(url, forms):
    payloads = ['../etc/passwd', '../../boot.ini']
    for form in forms:
        for payload in payloads:
            response, form_action = send_form_request(url, form, payload, form.get('method', 'get'))
            if response and ("root:" in response.text or "[boot loader]" in response.text):
                print(f"Potential File Download Vulnerability at {form_action}")

# 위치 공개 점검
def detect_location_disclosure(url, forms):
    payload = 'test'
    for form in forms:
        response, form_action = send_form_request(url, form, payload, form.get('method', 'get'))
        if response and "latitude" in response.text.lower() and "longitude" in response.text.lower():
            print(f"Potential Location Disclosure at {form_action}")


#--------------------------------------------------------------------------------
# 여기부터 수정하거나 다듬어야할 메소드입니다
# -------------------------------------------------------------------------------
            
# 로그인 페이지 식별 함수(다른 메소드에 필요)
def is_login_page(form):
    input_types = {input_tag.get('type', 'text').lower() for input_tag in form.find_all('input')}
    return 'password' in input_types and ('text' in input_types or 'email' in input_types)

# 약한 문자열 강도 취약점
def detect_weak_password(session, login_url, username_field, password_field):
    weak_passwords = [
        "admin", "administrator", "manager", "guest", "test", "scott", "tomcat", "root", "user", "operator", "anonymous",
        "abcd", "aaaa", "1234", "1111", "password", "public", "black"
    ]
    users = ["admin", "administrator", "manager", "guest", "test", "scott", "tomcat", "root", "user", "operator", "anonymous"]

    for user in users:
        for pwd in weak_passwords:
            login_data = {username_field: user, password_field: pwd}
            response = session.post(login_url, data=login_data)
            if response.status_code == 200 and "login" not in response.text.lower():
                print(f"Potential Weak Password for user '{user}' with password '{pwd}' at {login_url}")
                return True
    return False

# directory indexing 취약점 탐지
# 코드로 보기 애매한 것 같은데, 확인을 더 해봐야할 것 같습니다
def detect_directory_indexing(url):
    pass


# main 함수
def main(start_url):
    visited = set()
    to_visit = {start_url}

    while to_visit:
        url = to_visit.pop()
        if url not in visited:
            visited.add(url)
            print(f"Crawling {url}")
            new_urls, forms = crawl(url, visited)
            to_visit.update(new_urls - visited)
            
            print(f"Testing {url}")
            detect_buffer_overflow(url, forms)
            detect_command_injection(url, forms)
            detect_ldap_injection(url, forms)
            detect_sql_injection(url, forms)
            detect_xpath_injection(url, forms)
            detect_information_disclosure(url, forms)
            detect_malicious_content(url, forms)
            detect_xss(url, forms)
            detect_insufficient_authentication(url, forms)
            detect_weak_password_recovery(url, forms)
            detect_csrf(url, forms)
            detect_insufficient_authorization(url, forms)
            detect_lack_of_process_validation(url, forms)
            detect_file_upload(url, forms)
            detect_file_download(url, forms)
            detect_location_disclosure(url, forms)

# 시작 URL 설정 및 실행
start_url = "http://example.com"
main(start_url)
