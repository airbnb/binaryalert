rule APT_UNC2452_Sunshuttle_Mar_2021_1 {
   meta:
      description = "Detect Sunshuttle implant used by UNC2452 group"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/Arkbird_SOLG/status/1367570764468224010"
      date = "2021-03-06"
      hash1 = "611458206837560511cb007ab5eeb57047025c2edc0643184561a6bf451e8c2c"
      hash2 = "b9a2c986b6ad1eb4cfb0303baede906936fe96396f3cf490b0984a4798d741d8"
      hash3 = "bbd16685917b9b35c7480d5711193c1cd0e4e7ccb0f2bf1fd584c0aebca5ae4c"
   strings:
      // check template builder
      $s1 = { 47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 39 59 72 42 6a 6b 6b 58 46 79 6b 62 47 51 72 6d 56 32 4b 49 2f 41 48 44 69 7a 57 51 61 4d 38 47 38 4a 37 6b 56 4b 32 56 65 2f 46 55 74 5f 6b 6b 53 56 6c 78 32 36 49 6e 46 56 61 79 70 77 2f 6c 75 5a 41 54 35 55 6e 55 69 34 64 4a 65 6b 6e 73 6b 55 6e 22 } // Go build ID: "9YrBjkkXFykbGQrmV2KI/AHDizWQaM8G8J7kVK2Ve/FUt_kkSVlx26InFVaypw/luZAT5UnUi4dJeknskUn"
      $s2 = { 47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 71 6f 66 49 6b 76 62 6c 73 31 69 72 4f 36 78 68 6a 41 63 5a 2f 6a 49 69 71 41 70 70 31 56 6f 39 72 4f 53 2d 44 6a 65 4e 75 2f 62 50 75 6e 33 4e 35 74 49 42 58 4b 50 74 4e 79 73 48 4f 51 2f 41 52 53 72 63 65 6b 35 68 51 47 38 59 49 56 6e 4d 75 37 54 22 } // Go build ID: "qofIkvbls1irO6xhjAcZ/jIiqApp1Vo9rOS-DjeNu/bPun3N5tIBXKPtNysHOQ/ARSrcek5hQG8YIVnMu7T" 
      // check OS commands + functions
      $s3 = { 6f 73 2f 65 78 65 63 2e 28 2a 43 6d 64 29 2e 52 75 6e } // os/exec.(*Cmd).Run
      $s4 = "main.request_session_key" fullword ascii
      $s5 = "main.wget_file" fullword ascii
      $s6 = "main.GetMD5Hash" fullword ascii
      $s7 = "main.beaconing"  fullword ascii
      $s8 = "main.resolve_command" fullword ascii
      $s9 = "main.send_file_part" fullword ascii
      $s10 = "main.retrieve_session_key" fullword ascii
      $s11 = "main.send_command_result" fullword ascii
      // Check Hyper-V MAC Address (anti-sandbox)
      $s12 = { 63 38 3a 32 37 3a 63 63 3a 63 32 3a 33 37 3a 35 61 } // c8:27:cc:c2:37:5a
      // check if public key is present
      $s13 = { 2d 2d 2d 2d 2d 42 45 47 49 4e } // -----BEGIN 
      $s14 = { 2d 2d 2d 2d 2d 45 4e 44 } // -----END 
     condition:
      uint16(0) == 0x5a4d and filesize > 800KB and 12 of them
}
