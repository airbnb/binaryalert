import "pe"

rule APT28_Zekapab_June_2020_1 {
   meta:
      description = "Detect Delphi variant of Zekapab"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/DrunkBinary/status/1276573779037163520"
      date = "2020-06-28"
      hash1 = "12879b9d8ae046ca2f2ebcc7b1948afc44e6e654b7f4746e7a5243267cfd7c46"
   strings:
      $s1 = "54484520494E535452554354494F4E2041542030783763663538326164205245464552454E434544204D454D4F525920415420307830303030303030302E2054" ascii /* hex encoded string 'THE INSTRUCTION AT 0x7cf582ad REFERENCED MEMORY AT 0x00000000. THE MEMORY COULD NOT BE READ.' */
      $s2 = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii
      $s3 = "5C4164646974696F6E735C73616D636C69656E742E657865" ascii /* hex encoded string '\Additions\samclient.exe' */
      $s4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" fullword ascii
      $s5 = "\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\" fullword ascii
      $s6 = "Software\\Borland\\Delphi\\Locales" fullword ascii
      $s7 = "SOFTWARE\\Borland\\Delphi\\RTL" fullword ascii
      $s8 = "Software\\Borland\\Locales" fullword ascii
      $s9 = "FastMM Borland Edition" fullword ascii
      $s10 = "#7@Qhq\\1@NWgyxeH\\_bpdgc" fullword ascii
      $s11 = "4150504C49434154494F4E204552524F52" ascii /* hex encoded string 'APPLICATION ERROR' */
      $s12 = "436D442E457865202F6320" ascii /* hex encoded string 'CmD.Exe /c ' */
      $s13 = "6572726F72" ascii /* hex encoded string 'error' */
      $s14 = "WndProcPtr" fullword ascii  
      $s15 = "Request.UserAgent" fullword ascii
      $s16 = "ProxyPassword<" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and ( pe.imphash() == "dbdfe8b60c1de0a9201044b3e91b9502" or 12 of them )
}
