import requests
from bs4 import BeautifulSoup

# 웹사이트 URL 설정
url = 'test'

# 불충분한 인증 점검
def check_authentication(url):
    session = requests.Session()
    response = session.get(url + '/dashboard')
    if response.status_code == 200 and 'Login' not in response.text:
        print("불충분한 인증 취약점이 발견!")
    else:
        print("불충분한 인증 취약점이 발견되지 않았습니다.")

# 취약한 패스워드 복구 점검
def check_weak_password_recovery(url):
    email = 'test@com'
    response = requests.post(url + '/reset_password', data={'email': email})
    #취약점 문구 확인?

# CSRF 점검
def check_csrf(url):
    session = requests.Session()
    response = session.get(url + '/form')
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf_token'})
    if csrf_token:
        print("CSRF 토큰이 존재합니다.")
    else:
        print("CSRF 취약점이 발견되었습니다!")

# 불충분한 인가 점검
def check_authorization(url):
    session = requests.Session()
    session.post(url + '/login', data={'username': 'user', 'password': 'password'})
    response = session.get(url + '/admin')
    if response.status_code == 200  not in response.text:
        print("불충분한 인가 취약점이 발견되었습니다!")
    else:
        print("불충분한 인가 취약점이 발견되지 않았습니다.")

# 프로세스 검증 누락 점검
def check_lack_of_process_validation(url):
    response = requests.post(url + '/transfer', data={'amount': '1000000'})
    if "Invalid transfer amount" not in response.text:
        print("프로세스 검증 누락 취약점이 발견되었습니다!")
    else:
        print("프로세스 검증 누락 취약점이 발견되지 않았습니다.")

# 파일 업로드 점검
def check_file_upload(url):
    files = {'file': ('test.txt', 'This is a test file')}
    response = requests.post(url + '/upload', files=files)
    if response.status_code == 200:
        print("파일 업로드 테스트가 성공했습니다.")
    else:
        print("파일 업로드 취약점이 발견되었습니다!")

# 파일 다운로드 점검
def check_file_download(url):
    response = requests.get(url + '/download/test.txt')
    if response.status_code == 200:
        print("파일 다운로드 테스트가 성공했습니다.")
    else:
        print("파일 다운로드 취약점이 발견되었습니다!")

# 위치 공개 점검
def check_location_disclosure(url):
    response = requests.get(url + '/location')
    if "latitude" in response.text or "longitude" in response.text:
        print("위치 공개 취약점이 발견되었습니다!")
    else:
        print("위치 공개 취약점이 발견되지 않았습니다.")


