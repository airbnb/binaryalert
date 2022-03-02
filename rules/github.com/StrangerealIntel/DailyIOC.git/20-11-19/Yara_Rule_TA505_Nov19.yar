import "pe"

rule TA505_bin_21Nov_1 {
   meta:
      description = "module1.bin"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/58_158_177_102/status/1197432303057637377"
      date = "2019-11-21"
      hash1 = "bfe610790d41091c37ae627472f5f8886357e713945ca8a5e2b56cd6c791f989"
   strings:
      $s1 = "intc.dll" fullword ascii
      $s2 = "?%?2?7?=?" fullword ascii /* hex encoded string ''' */
      $s3 = "Is c++ not java" fullword ascii
      $s4 = "4%5K5e5l5p5t5x5|5" fullword ascii
      $s5 = "KdaMt$" fullword ascii
      $s6 = ";*;9;Z;`;" fullword ascii
      $s7 = "<*<4<?<I<S<Y<" fullword ascii
      $s8 = "0'040A0K0U0]0k0" fullword ascii
      $s9 = "3 3(30363>3M3_3" fullword ascii
      $s10 = ": :9:A:F:R:W:t:z:" fullword ascii
      $s11 = "5'5,585@5H5P5f5n5v5~5" fullword ascii
      $s12 = "<,<2<:<@<h<n<" fullword ascii
      $s13 = "8+808:8T8b8j8p8" fullword ascii
      $s14 = "8!9<9K9g9o9z9" fullword ascii
      $s15 = ">(>6>D>N>U>f>p>" fullword ascii
      $s16 = ":!:,:>:J:X:^:c:i:v:" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      ( pe.imphash() == "642f4619fb2d93cb205c65c2546516ca" and pe.exports("intc") or 8 of them )
}

rule TA505_bin_21Nov_2 {
   meta:
      description = "vspub1.bin"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/58_158_177_102/status/1197432303057637377"
      date = "2019-11-21"
      hash1 = "54cc27076793d5de064813c61d52452d42f774d24b3859a63002d842914fd9cd"
   strings:
      $s1 = "glColor.dll" fullword ascii
      $s2 = "{sysdir}\\nvu*.exe" fullword ascii
      $s3 = "KLSUIrhekheirguhemure" fullword ascii
      $s4 = "tEo>qM" fullword ascii
      $s5 = "?\"?0?8?>?I?V?^?l?q?v?{?" fullword ascii
      $s6 = ";\";0;d;" fullword ascii
      $s7 = "T0p0v0|0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      ( pe.imphash() == "ff6dd5f31dd7c538ebc02542f09f4280" and pe.exports("setColor") or all of them )
}

rule TA505_Maldoc_21Nov_1 {
   meta:
      description = "invitation.doc"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/58_158_177_102/status/1197432303057637377"
      date = "2019-11-21"
      hash1 = "a197c6de8734044c441438508dd3ce091252de4f98df2016b006a1c963c02505"
   strings:
      $x1 = "C:\\Users\\J\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.MSO\\basecamp" fullword wide
      $x2 = "*\\G{42DC991A-7E1B-4254-B210-CDD3DDCFD365}#2.0#0#C:\\Users\\1\\AppData\\Local\\Temp\\VBE\\MSForms.exd#Microsoft Forms 2.0 Object" wide
      $x3 = "*\\G{0D452EE1-E08F-101A-852E-02608C4D0BB4}#2.0#0#C:\\Windows\\system32\\FM20.DLL#Microsoft Forms 2.0 Object Library" fullword wide
      $x4 = "C:\\Users\\J\\AppData\\Local\\Temp\\basecamp" fullword wide
      $s5 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide
      $s6 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual" wide
      $s7 = "glColor.dll" fullword ascii
      $s8 = "magne.dll" fullword ascii
      $s9 = "InitScope.dll" fullword wide
      $s10 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\system32\\stdole2.tlb#OLE Automation" fullword wide
      $s11 = "CopyFiles=@EP0NGJ8D.GPD,@EP0NGN8D.GPD,@EP0NGX8D.GPD,@EP0NCJ8D.CMB,@EP0NOJ8D.DXT,@EP0NOE10.DLL,@EP0NM4RC.DLL,@EP0NRE8D.DLL" fullword wide
      $s12 = "CopyFiles=@EP0NGJ8C.GPD,@EP0NGN8C.GPD,@EP0NGX8C.GPD,@EP0NCJ8C.CMB,@EP0NOJ8C.DXT,@EP0NOE09.DLL,@EP0NM4RB.DLL,@EP0NRE8C.DLL" fullword wide
      $s13 = "vspub2.dll-" fullword ascii
      $s14 = "pictarget" fullword ascii
      $s15 = "Public Declare Function ZooDcom Lib        \"vspub1.dll\" Alias \"IKAJSL\" () As Integer" fullword ascii
      $s16 = "\"Epson\"=\"http://go.microsoft.com/fwlink/?LinkID=36&prd=10798&sbp=Printers\"" fullword wide
      $s17 = "EP0NM4RC.DLL = 1" fullword wide
      $s18 = "EP0NOE10.DLL = 1" fullword wide
      $s19 = "EP0NRE8C.DLL = 1" fullword wide
      $s20 = "EP0NM4RB.DLL = 1" fullword wide
   condition:
      uint16(0) == 0xcfd0 and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule TA505_Maldoc_21Nov_2 {
   meta:
      description = "invitation (1).xls"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/58_158_177_102/status/1197432303057637377"
      date = "2019-11-21"
      hash1 = "270b398b697f10b66828afe8d4f6489a8de48b04a52a029572412ae4d20ff89b"
   strings:
      $x1 = "C:\\Users\\J\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.MSO\\AFFA0BDC.tmp" fullword wide
      $x2 = "C:\\Users\\J\\AppData\\Local\\Temp\\AFFA0BDC.tmp" fullword wide
      $x3 = "C:\\Windows\\system32\\FM20.DLL" fullword ascii
      $x4 = "C:\\Users\\J\\AppData\\Local\\Temp\\VBE\\MSForms.exd" fullword ascii
      $x5 = "C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii
      $x6 = "C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii
      $x7 = "*\\G{0D452EE1-E08F-101A-852E-02608C4D0BB4}#2.0#0#C:\\Windows\\system32\\FM20.DLL#Microsoft Forms 2.0 Object Library" fullword wide
      $x8 = "*\\G{BA45F137-16B2-487D-9A21-F38179C0576C}#2.0#0#C:\\Users\\J\\AppData\\Local\\Temp\\VBE\\MSForms.exd#Microsoft Forms 2.0 Object" wide
      $s9 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide
      $s10 = "lIySgefa86jIfdEkSZVDoSs5BDkcalCieNBN4EqfVaEs2wWD4OjpTiOBqDrL3d9WCaDAKZpoJPRnoacfQPhucmy69axznNmRbRY12v3ez5PdAAnpAl5m5NUqKHBKCYb5" ascii
      $s11 = "35mvkZ9ZvIttuHSTUKWZCdOsh5j4Y1p2pJ3vi5onOXnMcEPIUIK1UWAYq3noPeaDtAdUOxKYvIlNZbqMpJjqpxhCidfpQ9GJXStKA44w7UFlKV9oMK8f5Tn6tKMKsviw" ascii
      $s12 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual" wide
      $s13 = "verkar.dll" fullword ascii
      $s14 = "intc.dll" fullword ascii
      $s15 = "YjAygups4wPzNU7lNIGBuFbv6Triw8rxEPLSjrYSKXdUV8QuzbwJvdHshfBvdh66er47iobvTX1FCqI8d6RuKRcBhsLdYCOC1hPEdTllabYHlcZ1FDsgyLuwoCZYM7Fq" ascii
      $s16 = "MinuetsOs.dll" fullword wide
      $s17 = "KaBYL8xLRpN7VMzibXEzxh2GetwfB6MY9k3dRCNncC5eiyKNTaTrcoUDi4TrLrkULX7KSvAHjrw4lXxPRSvBmvWUzz5WRwKTskBtBa4xIlhT1ZruGeI36SIqamksANYW" ascii
      $s18 = "XmhvJDfd16Hxk6eRMKJ7sqYIVneFVN7iUzRF8or7LKNKW9bhf5a7V5OGwIIvyJrm8yMUoITytLvRMoVWm7z1NawYTkjzP5HbtBLxwp3GkLMjJ74iWVjBjzI8cWadyuRy" ascii
      $s19 = "Sx3mdokmfv27AYhtFublOb5Exec1r1b5LAAbsRHrjLKTWiG4K9dKXbuQBxY9mt4nu7u9ygaWWTcczlRpGhpsXzgKgTI52IfZRxyZWHFD8pXd9sqqOJBedLy4ZT3OHe5n" ascii
      $s20 = "C:\\Windows\\system32\\stdole2.tlb" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 5000KB and
      1 of ($x*) and 4 of them
}
