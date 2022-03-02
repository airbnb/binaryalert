import "pe"

rule Malware_Casbaneiro_MSI {
   meta:
      description = "Detect MSIPackage used by Casbaneiro"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/JAMESWT_MHT/status/1268811438707159040"
      date = "2020-06-05"
      hash1 = "8e77a2e1d30600db01a8481d232b601581faee02b7ec44c1ad9d74ec3544ba7d"
   strings:
      $x1 = "C:\\Branch\\win\\Release\\custact\\x86\\vmdetect.pdb" fullword ascii
      $s2 = "C:\\Branch\\win\\Release\\custact\\\\x86\\AICustAct.pdb" fullword ascii
      $s3 = ";!@Install@!UTF-8!\\nTitle=\"Mozilla Firefox\"\\nRunProgram=\"setup-stub.exe\"\\n;!@InstallEnd@!7z" fullword ascii
      $s4 = "__MOZCUSTOM__:campaign%3D%2528not%2Bset%2529%26content%3D%2528not%2Bset%2529%26medium%3Dreferral%26source%3Dwww.google.com" fullword ascii
      $s5 = "https://www.mozilla.com0\\r" fullword wide
      $s6 = "__CxxFrameHandler" fullword ascii
      $s7 = "release+certificates@mozilla.com" fullword ascii
      $s8 = "setup-stub.exe" fullword ascii
      $s9 = "7zS.sfx.exe" fullword ascii
   condition:
      uint16(0) == 0xd0cf and filesize > 100KB and 7 of them
}
