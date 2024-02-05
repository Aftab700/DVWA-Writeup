# JavaScript Attacks


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

