
/* As Reference for the structure to catch -> https://unit42.paloaltonetworks.com/wp-content/uploads/2016/10/OilRig_5.png */

rule APT_OilRig_VBS_2016_1 {
   meta:
      description = "Detect VBS script in base 64 used by OilRig (2016)"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/Arkbird_SOLG/status/1298758788028264450"
      date = "2020-08-26"
      hash1 = "1edbb818ea75919bb70bd2496e789e89d26c94cdf65ab61ebb5f1403d45d323c"
      hash2 = "1191d5c1dd7f6ac38b8d72bee37415b3ff1c28a8f907971443ac3a36906e8bf5"
   strings:
      $block1 = { 53 45 39 4e 52 54 30 69 4a 58 42 31 59 6d 78 70 59 79 56 63 54 47 6c 69 63 6d 46 79 61 57 56 7a 58 43 49 } //  HOME="%public%\Libraries\"
      $block2 = { 43 6c 4e 46 55 6c 5a 46 55 6a 30 69 61 48 52 30 } // SERVER="http
      $block3 = { 56 34 4c 6d 46 7a 63 48 67 2f 63 6d 56 78 } // .aspx?req=
      $block4 = { 6a 30 69 63 47 39 33 5a 58 4a 7a 61 47 56 73 62 43 41 69 49 69 5a 37 4a 48 64 6a 50 53 68 75 5a 58 63 74 62 32 4a 71 5a 57 4e 30 49 46 4e 35 63 33 52 6c 62 53 35 4f 5a 58 51 75 56 32 56 69 51 32 78 70 5a 57 35 30 4b 54 73 6b 64 32 4d 75 56 58 4e 6c 52 47 56 6d 59 58 56 73 64 45 4e 79 5a 57 52 6c 62 6e 52 70 59 57 78 7a 50 53 52 30 63 6e 56 6c 4f 79 52 33 59 79 35 49 5a 57 46 6b 5a 58 4a 7a 4c 6d 46 6b 5a 43 67 6e 51 57 4e 6a 5a 58 42 30 4a 79 77 6e 4b 69 38 71 4a 79 6b 37 4a 48 64 6a 4c 6b 68 6c 59 57 52 6c 63 6e 4d 75 59 57 52 6b 4b 43 64 56 63 32 56 79 4c 55 46 6e 5a 57 35 30 4a 79 77 6e 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 49 45 4a 4a 56 46 4d 76 4e 79 34 33 4a 79 6b 37 64 32 68 70 62 47 55 6f 4d 53 6c 37 64 48 4a 35 65 79 52 79 50 55 64 6c 64 43 31 53 59 57 35 6b 62 32 30 37 4a 48 64 6a 4c 6b 52 76 64 32 35 73 62 32 46 6b 52 6d 6c 73 } // powershell ""&{$wc=(new-object System.Net.WebClient);$wc.UseDefaultCredentials=$true;$wc.Headers.add('Accept','*/*');$wc.Headers.add('User-Agent','Microsoft BITS/7.7');while(1){try{$r=Get-Random;$wc.DownloadFile(
      $block5 = { 69 49 4e 43 6b 4e 79 5a 57 46 30 5a 55 39 69 61 6d 56 6a 64 43 67 69 56 31 4e 6a 63 6d 6c 77 64 43 35 54 61 47 56 73 62 43 49 70 4c 6c 4a 31 62 69 42 53 5a 58 42 73 59 57 [1-4] 45 52 33 62 69 77 69 4c 56 38 [1-4] 4a 6b 64 32 34 69 4b 53} // CreateObject("WScript.Shell").Run Replace([1-4],"-_","[1-4]"),0
      $block6 = { 30 69 49 69 49 4e 43 6b 4e 79 5a 57 46 30 5a 55 39 69 61 6d 56 6a 64 43 67 69 56 31 4e 6a 63 6d 6c 77 64 43 35 54 61 47 56 73 62 43 49 70 4c 6c 4a 31 62 69 42 53 5a 58 42 73 59 57 4e 6c 4b 45 52 76 64 32 35 73 62 32 46 6b 52 58 68 6c 59 33 56 30 5a 53 77 69 4c 56 38 69 4c 43 4a 69 59 58 51 } // CreateObject("WScript.Shell").Run Replace(DownloadExecute,"-_","bat"),0
      $block7 = { 51 70 72 62 32 31 6a 50 53 4a 77 62 33 64 6c 63 6e 4e 6f 5a 57 78 73 49 43 31 6c 65 47 56 6a 49 45 4a 35 63 47 46 7a 63 79 41 74 52 6d 6c 73 5a 53 41 69 4a 6b } // "powershell -exec Bypass -File "&HOME&"
      $block8 = { 0a b7 9a b5 e3 9b 8d e7 2d 59 27 2b 8a 9b 52 85 e9 65 46 e9 [1-4] d4 } // CreateObject("WScript.Shell").Run [1-4],0  
   condition:
      filesize < 2KB and 6 of them 
}

rule APT_OilRig_PSH_Helminth_2016_1 {
   meta:
      description = "Detect Powershell script Helminth in base 64 used by OilRig (2016)"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/Arkbird_SOLG/status/1298758788028264450"
      date = "2020-08-26"
      hash1 = "1edbb818ea75919bb70bd2496e789e89d26c94cdf65ab61ebb5f1403d45d323c"
      hash2 = "1191d5c1dd7f6ac38b8d72bee37415b3ff1c28a8f907971443ac3a36906e8bf5"
   strings:
      $block1 = { 70 74 65 57 6c 6b 49 44 30 67 4a 79 4d 6a 49 79 63 67 44 51 6f 67 4a 47 64 73 62 32 4a 68 62 44 70 74 65 57 68 76 62 57 55 67 50 53 41 69 4a 47 56 75 64 6a 70 51 64 } // $global:myhome = "$env:Public\Libraries\"
      $block2 = { 41 67 ?? ?? 42 6c 62 48 4e 6c 61 57 59 6f 4a 47 31 35 5a 6d 78 68 5a 7a 4d 67 4c 57 56 78 49 44 49 70 49 41 30 4b 49 43 41 67 49 48 73 67 44 51 6f 67 49 43 41 67 49 43 41 67 49 43 67 6e 64 33 63 6e 4b 79 52 6e 62 47 39 69 59 57 77 36 62 58 6c 70 5a 43 73 6b 59 32 31 6b 61 57 51 72 4a 48 42 68 63 6e 52 70 5a 43 73 6f } //  '??'+$global:myid+$cmdid+$partid+(convertTo-Base36(Get-Random -Maximum 46655)))
      $block3 = { 6a 61 47 46 79 58 53 42 62 61 57 35 30 58 53 41 6b 64 47 31 77 57 7a 42 64 4b 53 41 72 49 43 } // .Equals('35.35.35.35')
      $block4 = { 43 52 6a 62 6e 51 67 4c 57 56 78 49 44 49 31 4b 53 6b 67 44 51 6f 67 49 43 41 67 65 79 41 } // .StartsWith('33.33.'))
      $block5 = { 5a 6c 52 45 35 54 49 43 67 6b 5a 43 6b 67 44 51 70 37 49 41 30 4b 43 53 52 6a 62 6e 51 67 50 53 41 77 49 41 30 4b 43 58 64 6f 61 57 78 6c 49 43 67 6b 59 32 35 30 49 43 31 73 64 43 41 79 4d 43 6b 67 44 51 6f 4a 65 79 41 4e 43 67 6b 4a 64 48 4a 35 49 41 30 4b 43 51 6c 37 } // ([System.Net.DNS]::GetHostByName($d+$global:myhost).AddressList[0])
      $block6 = { 4b 49 43 41 67 49 43 41 67 49 43 41 6b 61 53 73 72 49 41 30 4b 49 43 41 67 49 48 30 67 44 51 6f 67 49 43 41 67 61 57 59 6f 4a 48 4a 6c 64 43 41 74 5a 58 45 67 4d 53 6b 67 44 51 6f 67 49 43 41 } // ($global:myhome+'tp\\'+$global:filename+".bat")
      $block7 = { 77 36 62 58 6c 6d 62 47 46 6e 49 44 30 67 4d 43 41 4e 43 69 41 67 49 43 42 39 49 41 30 4b 49 43 41 67 49 47 56 73 63 32 56 70 5a 69 41 6f 4a 47 64 73 62 32 4a 68 62 44 70 74 65 57 5a 73 59 57 63 67 4c 57 56 78 49 44 45 70 49 41 30 4b 49 43 41 67 49 48 73 67 44 51 6f 67 49 43 41 67 49 43 41 67 49 43 52 30 62 58 41 67 50 53 41 6b 62 58 6c 6b 59 58 52 68 4c 6c 4e 77 62 47 6c 30 4b 43 63 75 4a 79 6b 67 44 51 6f 67 49 43 41 67 49 43 41 67 49 46 74 54 65 58 4e 30 5a 57 30 75 53 55 38 75 52 6d 6c 73 5a 56 30 36 4f 6b 46 77 63 47 56 75 5a 45 46 73 62 46 52 6c 65 48 51 6f 4a 47 64 73 62 32 4a 68 62 44 70 74 65 57 68 76 62 57 55 72 4a 33 52 77 58 43 63 72 4a 47 64 73 62 32 4a 68 62 44 70 6d 61 57 78 6c 62 6d 46 74 } // [System.IO.File]::AppendAllText($global:myhome+'tp\'+$global:filename+".bat", (([char] [int] $tmp[0]) + ([char] [int] $tmp[1]) + ([char] [int] $tmp[2]) + ([char] [int] $tmp[3])))
      $block8 = { 4a 47 6b 72 4b 79 41 4e 43 69 41 67 49 43 42 39 49 41 30 4b 49 48 30 67 44 51 6f 67 44 51 6f 67 5a 6e 56 75 59 33 52 70 62 32 34 67 52 32 56 30 53 55 [1-10] 4e 43 69 41 67 49 43 41 6b 5a 32 78 76 59 6d 46 73 4f 6d 31 35 61 57 51 67 50 53 42 54 5a 57 35 6b 55 6d 56 6a 5a 57 6c 32 5a 55 52 4f 55 79 41 6f 4b 45 64 6c 64 46 4e 31 59 69 41 77 4b 53 73 6e 4d 7a 41 6e 4b 53 41 4e 43 69 42 39 49 41 30 4b 49 41 30 4b 49 47 5a 31 62 6d 4e 30 61 57 39 [1-10] 56 52 6f 61 58 4e 47} //  (Get-Content "$env:Public\Libraries\[1-10].ps1") -replace ('#'+'##'),$botid | Set-Content "$env:Public\Libraries\[1-10].ps1"
      $block9 = { 73 67 44 51 6f 4a 43 57 31 6b 49 43 31 47 62 33 4a 6a 5a 53 41 6f 4a 47 64 73 62 32 4a 68 62 44 70 74 65 57 68 76 62 57 55 72 4a 33 52 77 58 43 63 70 49 41 30 4b 43 51 6c 48 5a 58 52 4a 52 43 41 4e 43 67 6b 4a 51 32 68 68 62 6d 64 6c 56 47 68 70 63 30 5a 70 62 47 55 67 4a 47 64 73 62 32 4a 68 62 44 70 74 65 57 6c 6b 49 41 30 4b 49 43 41 67 49 48 30 67 44 51 6f 67 66 53 41 4e 43 69 42 6d 64 57 35 6a 64 47 6c 76 62 69 42 74 59 57 6c 75 49 41 30 4b } //  Invoke-Expression ($global:myhome+'tp\'+$global:filename+'.bat > '+$global:myhome+'tp\'+$global:filename+'.txt')
   condition:
      filesize < 3KB and 7 of them 
}
