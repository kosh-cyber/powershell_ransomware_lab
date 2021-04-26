# Powershell ransomware LAB
## Date: April 1 2021 

## Description:
A Simple Powersell 3.0 Script Can easier and faster to Encrypt/Decrypt File in assign extensions.
The size of these encrypted files will not exceed 2G.
### Docker Build
docker build -t ransomware_lab .
docker run -it -p 8080:8080 ransomware_lab
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
Decrypt:
	modify script/decrypt.ps1 url "http://10.10.10.4:3000/session"
		
### Encrypt/Decrypt File Process:
![](https://raw.githubusercontent.com/kosh-cyber/powershell_ransomware_lab/main/Encrypt-Decrypt.png)
### Decrypt Session from remote host
![](https://raw.githubusercontent.com/kosh-cyber/powershell_ransomware_lab/main/decryptsession.JPG)
### Encrypt File List
![](https://raw.githubusercontent.com/kosh-cyber/powershell_ransomware_lab/main/encryptfile.JPG)
### Don't do Evil
