rule APT_KimSuky_bckdr_dll {

   meta:

      description = "Armadillo packed DLL used in Kimsuky campaign"
      author = "Christiaan Beek - McAfee Advanced Threat Research"
      date = "2018-02-09"
      rule_version = "v1"
      malware_type = "backdoor"
      malware_family = "Backdoor:W32/Kimsuky"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://securelist.com/the-kimsuky-operation-a-north-korean-apt/57915/"
      hash = "afe4237ff1a3415072d2e1c2c8954b013471491c6afdce3f04d2f77e91b0b688"

   strings:

      $x1 = "taskmgr.exe Execute Ok!!!" fullword ascii
      $x2 = "taskmgr.exe Execute Err!!!" fullword ascii
      $x3 = "kkk.exe Executing!!!" fullword ascii
      $s4 = "ShellExecuteA Ok!!!" fullword ascii
      $s5 = "ShellExecuteA Err!!!" fullword ascii
      $s6 = "Manage.dll" fullword ascii
      $s7 = "%s_%s.txt" fullword ascii
      $s8 = "kkk.exe Copy Ok!" fullword ascii
      $s9 = "File Executing!" fullword ascii
      $s10 = "////// KeyLog End //////" fullword ascii
      $s11 = "//////// SystemInfo End ///////" fullword ascii
      $s12 = "//////// SystemInfo ///////" fullword ascii
      $s13 = "///// UserId //////" fullword ascii
      $s14 = "///// UserId End //////" fullword ascii
      $s15 = "////// KeyLog //////" fullword ascii
      $s16 = "Decrypt Erro!!!" fullword ascii
      $s17 = "File Delete Ok!" fullword ascii
      $s18 = "Down Ok!!!" fullword ascii

      $op0 = { be 40 e9 00 10 8d bd 3c ff ff ff 83 c4 48 f3 a5 }
      $op1 = { 8b ce 33 c0 8b d1 8d bc 24 34 02 00 00 c1 e9 02 }
      $op2 = { be dc e9 00 10 8d bd 1c ff ff ff f3 a5 8d bd 1c }
   
   condition:

      ( uint16(0) == 0x5a4d and 
      filesize < 200KB and 
      ( 1 of ($x*) and 
      4 of them ) and 
      all of ($op*)) or 
      ( all of them )
}

