# DOM Based Cross Site Scripting (XSS)


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
