import "pe"

rule syskit {
   meta:
      description = "SYSkit backdoor"
      author = "Christiaan @ McAfee ATR"
      reference = "https://www.symantec.com/blogs/threat-intelligence/tortoiseshell-apt-supply-chain"
      date = "2019-09-17"
      hash1 = "07d123364d8d04e3fe0bfa4e0e23ddc7050ef039602ecd72baed70e6553c3ae4"
      hash2 = "f71732f997c53fa45eef5c988697eb4aa62c8655d8f0be3268636fc23addd193"
      hash3 = "02a3296238a3d127a2e517f4949d31914c15d96726fb4902322c065153b364b2"
   strings:
      $x1 = "timeout /t 10 & sc stop dllhost & timeout /t 10 & del C:\\Windows\\Temp\\BAK.exe" fullword wide
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s3 = "C:\\Windows\\Temp\\rconfig.xml" fullword wide
      $s4 = "Add-Type -AssemblyName System.IO.Compression.FileSystem" fullword wide
      $s5 = "serviceProcessInstaller1" fullword ascii
      $s6 = "    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)" fullword wide
      $s7 = "exec_cmd2" fullword ascii
      $s8 = "exec_cmd" fullword ascii
      $s9 = "send_command_result" fullword ascii
      $s10 = "mycontent" fullword ascii
      $s11 = "Diagnostic Server Host" fullword wide
      $s12 = "bytesToBeEncrypted" fullword ascii
      $s13 = "createPostRequest" fullword ascii
      $s14 = "myhash" fullword ascii
      $s15 = "DD5783BCF1E9002BC00AD5B83A95ED6E4EBB4AD5" ascii
      $s16 = "circle_time" fullword ascii
      $s17 = "ServiceStart_AfterInstall" fullword ascii
      $s18 = "serviceInstaller1" fullword ascii
      $s19 = "BAK.ProjectInstaller.resources" fullword ascii
      $s20 = "Dll host" fullword wide

      $op0 = { 96 00 f1 0a 57 02 05 00 34 25 }
      $op1 = { 96 00 83 05 5a 01 0e 00 38 28 }
      $op2 = { 06 00 00 11 28 4d 00 00 0a 02 6f 4e 00 00 0a 28 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them ) and all of ($op*)
      ) or ( all of them )
}
