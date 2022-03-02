import "pe"

rule APT_MAL_NK_Rivts_Feb_2009_1 {
   meta:
      description = "Detect Rivts malware used by NK APT"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/Arkbird_SOLG/status/1272674621381361672"
      date = "2020-06-17"
      hash1 = "244885b47ec2157a8ea9278bec3ea1883f45d97b1fcb78d4fa875bef0f329a97"
   strings:
      $s1 = "F:\\meWork\\ksj\\Test\\testVir-ga\\testvir_non\\Debug\\testvir_non.pdb" fullword ascii
      $s2 = "\\\\.\\pipe\\TESTVIR1PIPE" fullword ascii
      $s3 = "\\system32\\Hana80.exe" fullword ascii
      $s4 = "\\system32\\nnr60.exe" fullword ascii
      $s5 = { 54 45 53 54 56 49 52 31 5f 45 56 45 4e 54 5f 4f 42 4a } /* TESTVIR1_EVENT_OBJ */
      $s6 = "INFECT" fullword ascii
      $s7 = { 54 45 53 54 5f 5f 5f 41 43 43 45 53 53 5f 44 49 52 } /* TEST___ACCESS_DIR */
      $s8 = { 2e 70 69 66 } /* .pif */ 
      $s9 = { 2f 2f 2f 2f 44 41 45 4d 4f 4e } /* ////DAEMON */ 
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and 7 of them 
}
