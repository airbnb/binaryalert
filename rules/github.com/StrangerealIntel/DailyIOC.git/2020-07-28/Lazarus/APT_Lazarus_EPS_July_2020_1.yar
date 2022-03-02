import "pe"

rule APT_Lazarus_EPS_July_2020_1 {
   meta:
      description = " Detected Lazarus EPS script for download and execute the payload in base 64"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/spider_girl22/status/1287952503280082944"
      date = "2020-07-28"
      hash1 = "152c620980f0fc20a6eade0f5b726b98fc28392d84ce386a5fc1b0877ef446d7"
   strings:
      $s1 = { 63 64 20 2F 64 20 22 25 61 70 70 64 61 74 61 25 5C 4D 69 63 72 6F 73 6F 66 74 5C 49 6E 74 65 72 6E 65 74 20 45 78 70 6C 6F 72 65 72 22 } // cd /d "%appdata%\Microsoft\Internet Explorer"
      $s2 = { 46 75 6E 63 74 69 6F 6E 20 42 61 73 65 36 34 44 65 63 6F 64 65 28 42 79 56 61 6C 20 76 43 6F 64 65 29 } // Function Base64Decode(ByVal vCode)
      $s3 = { 43 72 65 61 74 65 4F 62 6A 65 63 74 28 22 4D 73 78 6D 6C 32 2E 44 4F 4D 44 6F 63 75 6D 65 6E 74 2E 33 2E 30 22 29 } // CreateObject("Msxml2.DOMDocument.3.0")
      $s4 = { 46 75 6E 63 74 69 6F 6E 20 42 69 6E 61 72 79 54 6F 53 74 72 69 6E 67 28 42 69 6E 61 72 79 29 } // Function BinaryToString(Binary)
      $s5 = { 43 72 65 61 74 65 4F 62 6A 65 63 74 28 22 41 44 4F 44 42 2E 53 74 72 65 61 6D 22 29 } //  CreateObject("ADODB.Stream")
      $s6 = { 43 72 65 61 74 65 4F 62 6A 65 63 74 28 22 57 53 63 72 69 70 74 2E 53 68 65 6C 6C 22 29 } // CreateObject("WScript.Shell")
      $s7 = { 63 72 65 61 74 65 6F 62 6A 65 63 74 28 22 4D 69 63 72 6F 73 6F 66 74 2E 58 4D 4C 48 54 54 50 22 29 } // createobject("Microsoft.XMLHTTP")
      $s8 = { 2E 45 6E 76 69 72 6F 6E 6D 65 6E 74 28 22 50 52 4F 43 45 53 53 22 29 28 22 50 72 6F 67 72 61 6D 57 36 34 33 32 22 29 20 3D 20 22 22 } // .Environment("PROCESS")("ProgramW6432") = ""
      $s9 = { 3A 43 72 65 61 74 65 4F 62 6A 65 63 74 28 22 53 63 72 69 70 74 69 6E 67 2E 46 69 6C 65 53 79 73 74 65 6D 4F 62 6A 65 63 74 22 29 2E 44 65 6C 65 74 65 66 46 69 6C 65 20 57 73 63 72 69 70 74 2E 53 63 72 69 70 74 46 75 6C 6C 4E 61 6D 65 2C 20 54 72 75 65 3E 22 } // CreateObject("Scripting.FileSystemObject").DeleteFile Wscript.ScriptFullName, True>"
      $s10 = { 20 65 63 68 6F 20 73 74 61 72 74 20 2F 42 20 2F 6D 69 6E 20 63 73 63 72 69 70 74 2E 65 78 65 } //  echo start /B /min cscript.exe
      $s11 = { 22 5E 26 64 65 6C 20 22 25 7E 66 30 22 3E } // "^&del "%~f0">
      $s12 = { 2E 52 75 6E 20 22 72 65 67 73 76 72 33 32 2E 65 78 65 20 2F 73 20 } // .Run "regsvr32.exe /s 
      $s13 = { 2E 54 79 70 65 20 3D 20 31 3A 2E 4F 70 65 6E 3A 2E 57 72 69 74 65 20 42 69 6E 61 72 79 3A 2E 50 6F 73 69 74 69 6F 6E 20 3D 20 30 3A 2E 54 79 70 65 20 3D 20 32 3A 2E 43 68 61 72 53 65 74 20 3D 20 22 75 73 2D 61 73 63 69 69 22 } // .Type = 1:.Open:.Write Binary:.Position = 0:.Type = 2:.CharSet = "us-ascii"
      $s14 = { 2E 4F 70 65 6E 20 22 47 45 54 22 2C 20 } // .Open "GET", 
      $s15 = { 73 74 61 72 74 20 2F 42 20 2F 6D 69 6E 20 } // start /B /min 
      $URL1 = { 22 68 74 74 70 3A 2F 2F 74 ?? ?? ?? } // "http://???
      $URL2 = { 22 68 74 74 70 73 3A 2F 2F 74 ?? ?? ?? } // "https://???
   condition:
      uint16(0) == 0x33c9 and filesize < 3KB  and (1 of ($URL*)) and (12 of ($s*))
}
