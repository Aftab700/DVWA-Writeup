# Stored Cross Site Scripting (XSS)


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
