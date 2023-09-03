from flask import Flask
import os, sys, time, re, datetime, random,requests
import time,os,sys,random,hashlib
from datetime import datetime
app = Flask(__name__)

xone = requests.Session()
def log_id(username, password):
        m = hashlib.md5()
        m.update(username.encode() + password.encode())

        seed = m.hexdigest()  
        vs = "12345"

        m = hashlib.md5()
        m.update(seed.encode('utf-8') + vs.encode('utf-8'))
        return 'android-' + m.hexdigest()[:16]
    
def genLoginHeaders(csrf, claim):
    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'q=0.9,en-US;q=0.8,en;q=0.7',
        'content-length': '0',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://www.instagram.com',
        'referer': 'https://www.instagram.com/',
        'sec-ch-ua':'" Not;A Brand";v="99", "Google Chrome";v="97", "Chromium";v="97"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36',
        'x-asbd-id': '198387',
        'x-csrftoken': csrf,
        'x-ig-app-id': '936619743392459',
        'x-ig-www-claim': claim,
        'x-instagram-ajax': '6ab3c34e0025',
        'x-requested-with': 'XMLHttpRequest'
    }
    return headers


def gen_client_id():
    letters = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"]
    ran4letters = ""
    for _ in range(4):
        if random.randint(0,1) == 0:
            ran4letters += letters[random.randrange(0,len(letters))]
        else:
            ran4letters += letters[random.randrange(0,len(letters))].upper()
    ran15chars = ""
    for _ in range(15):
        if random.randint(0,1) == 0:
            if random.randint(0,1) == 0:
                ran15chars += letters[random.randrange(0,len(letters))]
            else:
                ran15chars += letters[random.randrange(0,len(letters))].upper()
        else:
            ran15chars += str(random.randint(0,9))

    client_id = f'Yf{ran4letters}ALAAG{letters[random.randrange(0,len(letters))].upper() + ran15chars}'
    return client_id

def get_token():
    a = requests.get('https://www.instagram.com/accounts/emailsignup/').text
    token = a.split('csrf_token')[1].split("viewer")[0].replace('\"','').replace('\:','').replace('\,','').replace('\\','')
    return token
def get_user():
    api = xone.get('https://randomuser.me/api/?nat=GB&password=number,lower,10').json()
    first = api['results'][0]['name']['first']
    last = api['results'][0]['name']['last']
    final = first+last
    return final
    
def get_family():
    api = xone.get('https://randomuser.me/api/?nat=GB&password=number,lower,10').json()
    first = api['results'][0]['name']['first']
    last = api['results'][0]['name']['last']
    final = first+' '+last
    return final

   
def gen_ran_passw():
    letters = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"]
    chars = ["!","?","=","&","$","#"]
    random_password = ""
    oldvalue = ""
    choicelist = [0,1,2]
    for x in range(14):
        if oldvalue:
            choicelist.remove(oldvalue)
            value = choice(choicelist)
            choicelist.append(oldvalue)
        else:
            value = randbelow(3)
        if value == 0:
            if randbelow(2) == 0:
                random_password += letters[randbelow(len(letters))].upper()
            else:
                random_password += letters[randbelow(len(letters))]
        elif value == 1:
            random_password += chars[randbelow(len(chars))]
        elif value == 2:
            random_password += str(randbelow(10))
        oldvalue = value
    
    random_password += letters[randbelow(len(letters))].upper() + letters[randbelow(len(letters))]
    random_password += chars[randbelow(len(chars))] + str(randbelow(10))

    return random_password
    
def generate_email():
    api = xone.get('https://randomuser.me/api/?nat=GB&password=number,lower,10').json()
    
    nam = api['results'][0]['name']['first']
    jam = str(datetime.now().strftime("%X")).replace(':', '')
    ran = str(random.randrange(1000, 10000))
    dom = random.choice(['fexbox.org', 'chitthi.in', 'fextemp.com', 'any.pink', 'merepost.com'])
    email = f'{nam}.{jam}.{ran}@{dom}'
    return email

def get_code_cryptogmail(email):
    url = f'https://tempmail.plus/api/mails?email={email}'
    req = xone.get(url, headers={'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7','Accept-Encoding':'gzip, deflate','Accept-Language':'en-US,en;q=0.9','Pragma':'akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-extracted-values, akamai-x-get-ssl-client-session-id, akamai-x-get-true-cache-key, akamai-x-serial-no, akamai-x-get-request-id,akamai-x-get-nonces,akamai-x-get-client-ip,akamai-x-feo-trace','Sec-Ch-Ua':'','Sec-Ch-Ua-Mobile':'?1','Sec-Ch-Ua-Platform':'','Sec-Fetch-Dest':'document','Sec-Fetch-Mode':'navigate','Sec-Fetch-Site':'none','Sec-Fetch-User':'?1','Upgrade-Insecure-Requests':'1','User-Agent':'Mozilla/5.0 (Linux; Android 11; vivo 1918 Build/RP1A.200720.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/112.0.0000.00 Mobile Safari/537.36'}).json()
    code = re.search("'subject': '(.*?) is",str(req))
    if code == None:
        print(code)
        return None
    else:
         return code.group(1)


def check_acc_info(email_address,token,password,username,family):
    cookies = {
    'csrftoken': token,
    'mid': 'ZNqy8AALAAFskhZU5xyzNVT_W9b7',
    'ig_did': '16C40EB6-E483-44A1-A145-207154B94420',
    'ig_nrcb': '1',
    'datr': 'ZpXYZCE1mT6ymcOcG8HHXcUz',
}


    headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    # 'Accept-Encoding': 'gzip, deflate, br',
    'X-CSRFToken': token,
    'X-Instagram-AJAX': '1008024793',
    'X-IG-App-ID': '936619743392459',
    'X-ASBD-ID': '129477',
    'X-IG-WWW-Claim': '0',
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-Requested-With': 'XMLHttpRequest',
    'Origin': 'https://www.instagram.com',
    'Alt-Used': 'www.instagram.com',
    'Connection': 'keep-alive',
    'Referer': 'https://www.instagram.com/accounts/emailsignup/',
    # 'Cookie': 'csrftoken=w2XZH0Xl4X9wMJcL7NWiFS5NnOe6V2fo; mid=ZNqy8AALAAFskhZU5xyzNVT_W9b7; ig_did=16C40EB6-E483-44A1-A145-207154B94420; ig_nrcb=1; datr=ZpXYZCE1mT6ymcOcG8HHXcUz',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    # Requests doesn't support trailers
    # 'TE': 'trailers',
}


    data = f'enc_password=#PWD_INSTAGRAM_BROWSER:0:{int(time.time())}:{password}&email={email_address}&first_name={family}&username={username}&client_id=ZNqy8AALAAFskhZU5xyzNVT_W9b7&seamless_login_enabled=1&opt_into_one_tap=false'


    response = xone.post(
    'https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/',
    cookies=cookies,
    headers=headers,
    data=data,
)

    
    if 'errors' in response.text:
        print("Refreshing Register Information....")
        email_address = generate_email()
        password = '1234qwer@'#gen_ran_passw()
        family = get_family()
        username = get_user()+str(random.randrange(1000, 10000))
        check_acc_info(email_address,token,password,username,family)
        
        print("")
#check_acc_info(email_address,token,password,username,family)

def check_birthday(token):
    
    cookies = {
    'csrftoken': token,
    'mid': 'ZNqy8AALAAFskhZU5xyzNVT_W9b7',
    'ig_did': '16C40EB6-E483-44A1-A145-207154B94420',
    'ig_nrcb': '1',
    'datr': 'ZpXYZCE1mT6ymcOcG8HHXcUz',
}


    headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    # 'Accept-Encoding': 'gzip, deflate, br',
    'X-CSRFToken': token,
    'X-Instagram-AJAX': '1008024793',
    'X-IG-App-ID': '936619743392459',
    'X-ASBD-ID': '129477',
    'X-IG-WWW-Claim': '0',
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-Requested-With': 'XMLHttpRequest',
    'Origin': 'https://www.instagram.com',
    'Alt-Used': 'www.instagram.com',
    'Connection': 'keep-alive',
    'Referer': 'https://www.instagram.com/accounts/emailsignup/',
    # 'Cookie': 'csrftoken=w2XZH0Xl4X9wMJcL7NWiFS5NnOe6V2fo; mid=ZNqy8AALAAFskhZU5xyzNVT_W9b7; ig_did=16C40EB6-E483-44A1-A145-207154B94420; ig_nrcb=1; datr=ZpXYZCE1mT6ymcOcG8HHXcUz',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    # Requests doesn't support trailers
    # 'TE': 'trailers',
}


    data = {
    'day': '9',
    'month': '5',
    'year': '1998',
}


    response = xone.post(
    'https://www.instagram.com/api/v1/web/consent/check_age_eligibility/',
    cookies=cookies,
    headers=headers,
    data=data,
)


    if '"eligible_to_register":true' not in response.text:
        print(R+"Error In Birhday Data ...")


def send_verfiy(email_address,token):
    xone = requests.Session()
    cookies = {
    'csrftoken': token,
    'mid': 'ZNqy8AALAAFskhZU5xyzNVT_W9b7',
    'ig_did': '16C40EB6-E483-44A1-A145-207154B94420',
    'ig_nrcb': '1',
    'datr': 'ZpXYZCE1mT6ymcOcG8HHXcUz',
}


    headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    # 'Accept-Encoding': 'gzip, deflate, br',
    'X-CSRFToken': token,
    'X-Instagram-AJAX': '1008024793',
    'X-IG-App-ID': '936619743392459',
    'X-ASBD-ID': '129477',
    'X-IG-WWW-Claim': '0',
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-Requested-With': 'XMLHttpRequest',
    'Origin': 'https://www.instagram.com',
    'Alt-Used': 'www.instagram.com',
    'Connection': 'keep-alive',
    'Referer': 'https://www.instagram.com/accounts/emailsignup/',
    # 'Cookie': 'csrftoken=w2XZH0Xl4X9wMJcL7NWiFS5NnOe6V2fo; mid=ZNqy8AALAAFskhZU5xyzNVT_W9b7; ig_did=16C40EB6-E483-44A1-A145-207154B94420; ig_nrcb=1; datr=ZpXYZCE1mT6ymcOcG8HHXcUz',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    # Requests doesn't support trailers
    # 'TE': 'trailers',
}


    data = f'device_id=ZNqy8AALAAFskhZU5xyzNVT_W9b7&email={email_address}'


    response = xone.post(
    'https://www.instagram.com/api/v1/accounts/send_verify_email/',
    cookies=cookies,
    headers=headers,
    data=data,
)


    
    
    if '"email_sent":true' in response.text:
        print("Sending Email Code .....")
        print("")
        

    else:
    	return render_template("index.html", state="Failed",email="Null",username="Null",password="Null")
        
        
        print("")



def check_vefriy_code(email_address,token,code,family, username,password):
    xone = requests.Session()
    cookies = {
    'csrftoken': token,
    'mid': 'ZNqy8AALAAFskhZU5xyzNVT_W9b7',
    'ig_did': '16C40EB6-E483-44A1-A145-207154B94420',
    'ig_nrcb': '1',
    'datr': 'ZpXYZCE1mT6ymcOcG8HHXcUz',
}


    headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    # 'Accept-Encoding': 'gzip, deflate, br',
    'X-CSRFToken': token,
    'X-Instagram-AJAX': '1008024793',
    'X-IG-App-ID': '936619743392459',
    'X-ASBD-ID': '129477',
    'X-IG-WWW-Claim': '0',
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-Requested-With': 'XMLHttpRequest',
    'Origin': 'https://www.instagram.com',
    'Alt-Used': 'www.instagram.com',
    'Connection': 'keep-alive',
    'Referer': 'https://www.instagram.com/accounts/emailsignup/',
    # 'Cookie': 'csrftoken=w2XZH0Xl4X9wMJcL7NWiFS5NnOe6V2fo; mid=ZNqy8AALAAFskhZU5xyzNVT_W9b7; ig_did=16C40EB6-E483-44A1-A145-207154B94420; ig_nrcb=1; datr=ZpXYZCE1mT6ymcOcG8HHXcUz',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    # Requests doesn't support trailers
    # 'TE': 'trailers',
}


    data = f'code={code}&device_id=ZNqy8AALAAFskhZU5xyzNVT_W9b7&email={email_address}'


    response = xone.post(
    'https://www.instagram.com/api/v1/accounts/check_confirmation_code/',
    cookies=cookies,
    headers=headers,
    data=data,
)


    if 'signup_code' in response.text:
        xone = requests.Session()
        code_hash = response.json()["signup_code"]
        print("Code Verified Successfully...")
        print("")
        cookies = {
    'csrftoken': token,
    'mid': 'ZNqy8AALAAFskhZU5xyzNVT_W9b7',
    'ig_did': '16C40EB6-E483-44A1-A145-207154B94420',
    'ig_nrcb': '1',
    'datr': 'ZpXYZCE1mT6ymcOcG8HHXcUz',
}


    
        headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    # 'Accept-Encoding': 'gzip, deflate, br',
    'X-CSRFToken': token,
    'X-Instagram-AJAX': '1008024793',
    'X-IG-App-ID': '936619743392459',
    'X-ASBD-ID': '129477',
    'X-IG-WWW-Claim': '0',
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-Requested-With': 'XMLHttpRequest',
    'Origin': 'https://www.instagram.com',
    'Alt-Used': 'www.instagram.com',
    'Connection': 'keep-alive',
    'Referer': 'https://www.instagram.com/accounts/emailsignup/',
    # 'Cookie': 'csrftoken=w2XZH0Xl4X9wMJcL7NWiFS5NnOe6V2fo; mid=ZNqy8AALAAFskhZU5xyzNVT_W9b7; ig_did=16C40EB6-E483-44A1-A145-207154B94420; ig_nrcb=1; datr=ZpXYZCE1mT6ymcOcG8HHXcUz',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    # Requests doesn't support trailers
    # 'TE': 'trailers',
}


    
        data = f"enc_password=#PWD_INSTAGRAM_BROWSER:0:{int(time.time())}:{password}&day=9&email={email_address}&first_name={family}&month=5&username={username}&year=1998&client_id=ZNqy8AALAAFskhZU5xyzNVT_W9b7&seamless_login_enabled=1&tos_version=row&force_sign_up_code={code_hash}"


    
        response = xone.post(
    'https://www.instagram.com/api/v1/web/accounts/web_create_ajax/',
    cookies=cookies,
    headers=headers,
    data=data,
).text

    
        
    
        
        print("Account Created Successfully ....")
        
        
           
         
        id = log_id(username,password) 
        payload = {
        'username': username,
        'device_id': id,
        'password': password}

        headers = {
        'Accept': '*/*',
        'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept-Language': 'en-US',
        'User-Agent': "Instagram 134.0.0.26.121 Android (28/9; 411dpi; 1080x2220; samsung; SM-A650G; SM-A650G; Snapdragon 450; en_US)",
        'referer' : "https://www.instagram.com/accounts/login/"
    }

        response = xone.post("https://i.instagram.com/api/v1/accounts/login/", headers=headers, data=payload)    
        if "logged_in_user" in response.text:
            acc = "* * * *  New Instagram Account  * * * *\n\nEmail <> "+email_address+"\n\nPasswors <> "+password+""
            xone.post(f"https://api.telegram.org/bot6615847959:AAHTH0BhAObVPyG7_8sl5pGZsji7f8kByzY/sendmessage?chat_id=6154741147&text={acc}")
            #insta_claim = response.headers["x-ig-set-www-claim"]
            return render_template("index.html", state="Created",email=email,username=username,password=password)
            csrf = xone.cookies.get_dict()["csrftoken"]
            
            #headers = genLoginHeaders(csrf, insta_claim)
        else:
            return render_template("index.html", state="Suspension",email="Null",username="Null",password="Null")
        ''' res = xone.get('https://www.instagram.com/accounts/login/')
        csrf = res.text.split('csrf_token":"')[1].split('"')[0]
        insta_claim = "0"

        
        payload = {
            'username': username,
            'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:{int(time.time())}:{password}',
            'queryParams': {},
            'optIntoOneTap': 'false'
        }

        #trying to login
        headers = genLoginHeaders(csrf, insta_claim)
        res =xone.post('https://www.instagram.com/accounts/login/ajax/', headers=headers, data=payload).text
        
        if 'authenticated' in res:
                
                acc = "* * * *  New Instagram Account  * * * *\n\nEmail <> "+email_address+"\n\nPasswors <> "+password+""
                xone.post(f"https://api.telegram.org/bot6615847959:AAHTH0BhAObVPyG7_8sl5pGZsji7f8kByzY/sendmessage?chat_id=6154741147&text={acc}")
                
        '''


@app.route('/')
def hello():
    return render_template("index.html", state="Start Page",email="Null",username="Null",password="Null")

@app.route('/go')
def ok():
    token = get_token()
    print(token)
    email_address = generate_email()
    password = '1234qwer@'#gen_ran_passw()
    family = get_family()
    username = get_user()+str(random.randrange(1000, 10000))
    check_acc_info(email_address,token,password,username,family)
    check_birthday(token)
    send_verfiy(email_address,token)
    print("Geting Verfiy Code ....")
    print("")
    time.sleep(13)
    code = get_code_cryptogmail(email_address)
    
    a = check_vefriy_code(email_address,token,code,family, username,password)
    

if __name__ == '__main__':
    app.run()