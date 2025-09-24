import requests
import urllib3
from base64 import b64encode
from datetime import datetime

class ZoomEyeClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False

        self.base_url = 'https://www.zoomeye.ai'

        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
        })

    def login(self, encrypted_password):
        """Login flow to ZoomEye"""
        try:
            print('[*] Step 1: Getting initial CSRF token...')
            resp1 = self.session.get(f'{self.base_url}/cas/api/user/userInfo')
            if resp1.status_code not in (200, 304):
                print(f'[!] Failed to get CSRF token. Status: {resp1.status_code}')
                return False

            csrf_token = self.session.cookies.get('_csrf')
            if not csrf_token:
                print('[!] CSRF token not found in cookies')
                return False
            print(f'[+] Got CSRF token: {csrf_token}')

            print('[*] Step 2: Getting SSO CSRF tokens...')
            resp2 = self.session.get(f'{self.base_url}/cas/api/index')
            if resp2.status_code not in (200, 304):
                print(f'[!] Failed to get SSO CSRF tokens. Status: {resp2.status_code}')
                return False

            sso_csrf = self.session.cookies.get('ssoCsrfToken')
            replace_sso_csrf = self.session.cookies.get('replaceSsoCsrfToken')
            if not sso_csrf or not replace_sso_csrf:
                print('[!] SSO CSRF tokens not found')
                return False
            print(f'[+] Got SSO tokens: {sso_csrf}, {replace_sso_csrf}')

            print('[*] Step 3: Attempting login...')
            login_data = encrypted_password

            resp3 = self.session.post(
                f'{self.base_url}/cas/api/cas/login',
                headers={'encode-X': 'change_it'},
                data=login_data,
            )

            if resp3.status_code == 201:
                print('[+] Login successful!')
                if self.session.cookies.get('sessionid'):
                    print('[+] Session established')
                    return True
                else:
                    print('[!] No session ID found after login')
                    return False
            else:
                print(
                    f'[!] Login failed. Status: {resp3.status_code}',
                    f'Response: {resp3.text}',
                    sep='\n',
                )
                return False

        except Exception as e:
            print(f'[!] Error during login: {e}')
            return False

    def search_pages(self, query, jwt, start_page, end_page):
        """Search ZoomEye from start_page to end_page"""
        if not self.session.cookies.get('sessionid'):
            print('[!] Not authenticated. Please login first.')
            return None

        search_url = f'{self.base_url}/api/search'
        headers = {'Cube-Authorization': jwt}

        # Base64 encode the query (ZoomEye format)
        b64query = b64encode(query.encode('utf-8'))

        results = []

        for i in range(start_page, end_page + 1):
            params = {
                'q': b64query,
                'page': str(i),
                'pageSize': 50,
            }

            print(f'[+] Получаем страницу {i}')
            response = self.session.get(search_url, headers=headers, params=params)
            if response.status_code == 200:
                matches = response.json().get('matches', [])
                for j in matches:
                    ip = j.get('ip')
                    port = j.get('portinfo', {}).get('port')
                    if ip and port:
                        results.append(f"{ip}:{port}")
            else:
                print(f'[!] Что-то пошло не так на странице {i}. Status: {response.status_code}')

        return results


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    client = ZoomEyeClient()
    encrypted_password = '"6OP6nY5/bJOV3EcJCBw9Z/3Zjb42/EJ3yit4tZbcvF/xlm7QCVXq5z40wz9PAuREbqyfNOJzOmAH+z4b181w0p5PeVd+lkva0aBeSBnUAcs1J4QOBfNT3eCMcAeKN9TIQ6cgG0nI6l0sinr6MJ5UrIvU89xJnUTeSiT5BFMSMjeLzp8KLycVS5TMm4q1wVf0"'  # RSA+Base64 пароль, как ждёт ZoomEye
    auth_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImlsbmF6bWlya2FzaW1vdkBnbWFpbC5jb20iLCJlbWFpbCI6ImlsbmF6bWlya2FzaW1vdkBnbWFpbC5jb20iLCJleHAiOjE3NTg4MTIyMjguMH0.fkrI6gN5hbaDF70eEGjOd6SgRLgBe-ClIz09u61gvu8'           # ваш Cube-Authorization JWT токен

    if client.login(encrypted_password):
        print("\n[+] Авторизация успешна. Можно вводить поисковые запросы.\n")

        while True:
            query = input('[?] Введите запрос (или quit/exit для выхода): ').strip()
            if query.lower() in ('quit', 'exit'):
                print('[*] Выход.')
                break

            try:
                start_page = int(input('[?] Первая страница: '))
                end_page = int(input('[?] Последняя страница: '))
            except ValueError:
                print('[!] Нужно ввести числа для страниц.')
                continue

            results = client.search_pages(query, auth_token, start_page, end_page)
            if results:
                filename = 'results.txt'
                with open(filename, 'a', encoding='utf-8') as f:
                    f.write("\n".join(results) + "\n")
                print(f'[+] Сохранено {len(results)} строк в {filename}')
            else:
                print('[!] Нет результатов или ошибка запроса.')
    else:
        print('[!] Login failed')
