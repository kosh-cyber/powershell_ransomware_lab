# Powershell ransomware LAB
## Date: April 1 2021 

## Description:
A Simple Powersell 3.0 Script Can easier and faster to Encrypt/Decrypt File in assign extensions.
The size of these encrypted files will not exceed 2G.
### How to Use:
	Encrypt:
		In Victim ENV
		you can use the function to genrate RSA 2048 bit key to replace encrypt.ps1 $pbkey
		$private_key can use https://github.com/MisterDaneel/PemToXml transform to pem 
		```
		function rsagen{
		$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList 2048
		$private_key = $rsa.toXmlString($true)
		$public_key = $rsa.toXmlString($false)
		return $private_key,$public_key
		}
        	$privatekey,$pubkey = rsagen
		```
		RUN encrypt.ps1
	Decrypt:
		Attacker ENV :
			python 3.7.9(python3.8 no support RSA time.clock)
			pycrypto package
			flask package
			your pem file
			RUN rsa.py
		In Vitcim
		modify decrypt.ps1 url "http://10.10.10.4:3000/session"
		RUN encrypt.ps1

### Encrypt File structure:
	Encrypt Session + Salt + EncryptFile
