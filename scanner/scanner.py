import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# 크롤링 함수 (재귀적 크롤링)
def crawl(url, visited):
    urls = set() #크롤링을 시작할 url
    forms = [] # 이미 방문한 url을 저장하는 집합(중복방문 피하기용)
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

# 버퍼 오버플로우 탐지 함수
def detect_buffer_overflow(url, forms):
    payload = 'A' * 10000 
    for form in forms:
        form_action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        form_data = {input_tag.get('name'): payload for input_tag in inputs if input_tag.get('name')}
        form_action = urljoin(url, form_action)
        
        try:
            if method == 'post':
                response = requests.post(form_action, data=form_data)
            else:
                response = requests.get(form_action, params=form_data)
            if response.status_code != 200: #오류가 나올 때 취약점이 있다고 판단
                print(f"Potential Buffer Overflow at {form_action}")
        except Exception as e:
            print(f"Error testing buffer overflow on {form_action}: {e}")

# 운영체제 명령 실행 취약점 탐지 함수
def detect_command_injection(url, forms):
    payloads = ["; ls", "&& ls", "| ls", "`ls`"] # 취약점 유발 페이로드
    for form in forms:
        form_action = urljoin(url, form.get('action'))
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        for payload in payloads:
            form_data = {input_tag.get('name'): payload for input_tag in inputs if input_tag.get('name')}
            try:
                if method == 'post':
                    response = requests.post(form_action, data=form_data)
                else:
                    response = requests.get(form_action, params=form_data)
                if "bin" in response.text or "boot" in response.text or "dev" in response.text: # bin, boot, dev가 포함되어 있다면 취약점 탐지
                    print(f"Potential Command Injection at {form_action}")
            except Exception as e:
                print(f"Error testing Command Injection on {form_action}: {e}")


# LDAP Injection 탐지 함수 - LDAP 를 사용해야 취약점을 볼 수 있다
def detect_ldap_injection(url, forms):
    payloads = ["*()|&'"] # LDAP Injection 유발할 수 있는 특수 문자 목록 - 추가가능
    for form in forms:
        form_action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        for payload in payloads:
            form_data = {input_tag.get('name'): payload for input_tag in inputs if input_tag.get('name')}
            form_action = urljoin(url, form_action)
            try:
                if method == 'post':
                    response = requests.post(form_action, data=form_data)
                else:
                    response = requests.get(form_action, params=form_data)
                if "LDAP" in response.text: # LDAP라는 리스폰이 오면 취약점 있다고 판단
                    print(f"Potential LDAP Injection at {form_action}")
            except Exception as e:
                print(f"Error testing LDAP Injection on {form_action}: {e}")

# SQL Injection 취약점 탐지
def detect_sql_injection(url, forms):
    payloads = ["' OR '1'='1", "' OR '1'='2"] # Injection 유발 키워드 - 추가 가능?
    for form in forms:
        form_action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        for payload in payloads:
            form_data = {input_tag.get('name'): payload for input_tag in inputs if input_tag.get('name')}
            form_action = urljoin(url, form_action)
            try:
                if method == 'post':
                    response = requests.post(form_action, data=form_data)
                else:
                    response = requests.get(form_action, params=form_data)
                if "SQL" in response.text or "syntax" in response.text: # SQL 혹은 syntax 구문이 뜨면 취약점
                    print(f"Potential SQL Injection at {form_action}")
            except Exception as e:
                print(f"Error testing SQL Injection on {form_action}: {e}")

# XPath Injection 취약점 탐지
def detect_xpath_injection(url, forms): # XML 데이터를 써야 탐지 가능 
    payloads = ["' or '1'='1"] # 취약점 유발 목록
    for form in forms:
        form_action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        for payload in payloads:
            form_data = {input_tag.get('name'): payload for input_tag in inputs if input_tag.get('name')}
            form_action = urljoin(url, form_action)
            try:
                if method == 'post':
                    response = requests.post(form_action, data=form_data)
                else:
                    response = requests.get(form_action, params=form_data)
                if "XPath" in response.text: # XPath 리스폰이면 취약점 탐지
                    print(f"Potential XPath Injection at {form_action}")
            except Exception as e:
                print(f"Error testing XPath Injection on {form_action}: {e}")

# 정보 누출 취약점
def detect_information_disclosure(url, forms): 
    # 지금은 완성하기 힘들고 테스트하면서 만져봐야할 것 같습니다
    sensitive_input_value = 'passwd'
    
    for form in forms:
        form_action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        form_data = {input_tag.get('name'): sensitive_input_value for input_tag in inputs if input_tag.get('name')}
        form_action = urljoin(url, form_action)

        try:
            if method == 'post':
                response = requests.post(form_action, data=form_data)
            else:
                response = requests.get(form_action, params=form_data)
            response_text = response.text.lower()

            # 중요 정보 키워드 검색
            if sensitive_input_value in response_text:
                print(f"Potential Information Disclosure at {form_action}: Found '{sensitive_input_value}' in response")
        except Exception as e:
            print(f"Error testing Information Disclosure on {form_action}: {e}")

# 악성 콘텐츠 취약점 탐지
def detect_malicious_content(url, forms):
    # 업로드 시도할 파일 목록 flash, avi, exe
    files_to_upload = {
        'flash': ('test.swf', b'%PDF-1.4 fake flash file content', 'application/x-shockwave-flash'),
        'video': ('test.avi', b'RIFF....AVI fake video file content', 'video/x-msvideo'),
        'executable': ('test.exe', b'MZP fake executable file content', 'application/octet-stream')
    }
    
    for form in forms:
        form_action = form.get('action')
        method = form.get('method', 'post').lower()  # 파일 업로드는 POST 메소드 사용
        inputs = form.find_all('input')
        form_action = urljoin(url, form_action)
        
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
                if response.status_code == 200 and file_name in response.text: # 파일 업로드가 가능했으면 취약점 탐지
                    print(f"Potential Malicious Content Upload at {form_action}: Uploaded '{file_name}'")
            except Exception as e:
                print(f"Error testing Malicious Content on {form_action}: {e}")

# XSS 공격 취약점 탐지
def detect_xss(url, forms):
    payload = "<script>alert('XSS')</script>" # XSS 공격을 시도하기 위한 페이로드
    for form in forms:
        form_action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        form_data = {input_tag.get('name'): payload for input_tag in inputs if input_tag.get('name')}
        form_action = urljoin(url, form_action)
        try:
            if method == 'post':
                response = requests.post(form_action, data=form_data)
            else:
                response = requests.get(form_action, params=form_data)
            if payload in response.text: # 페이로드가 포함되면 취약점 탐지
                print(f"Potential XSS at {form_action}")
        except Exception as e:
            print(f"Error testing XSS on {form_action}: {e}")
            
            

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

# 불충분한 인증 - 세션에 관한 것이 나오네요...
def detect_insufficient_authentication(url):
    pass


# main - 수정 중
def main(start_url):
    visited = set()
    to_visit = {start_url}

    session = requests.Session()
    
    while to_visit:
        url = to_visit.pop()
        if url not in visited:
            visited.add(url)
            print(f"Crawling {url}")
            new_urls, forms = crawl(url)
            to_visit.update(new_urls - visited)
            
            print(f"Testing {url}")
            detect_buffer_overflow(url, forms)
            detect_ldap_injection(url, forms)
            detect_sql_injection(url, forms)
            detect_xpath_injection(url, forms)
            detect_directory_indexing(url)
            detect_information_disclosure(url)
            detect_malicious_content(url)
            detect_xss(url, forms)
            detect_weak_password(url)
            detect_insufficient_authentication(url)

# 시작 URL 설정 및 실행
start_url = "http://example.com"
main(start_url)
