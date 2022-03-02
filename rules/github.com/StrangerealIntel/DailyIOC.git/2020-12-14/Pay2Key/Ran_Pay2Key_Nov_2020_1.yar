rule Ran_Pay2Key_Nov_2020_1 {
   meta:
      description = "Detect Pay2Key ransomware"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-12-01"
      hash1 = "5bae961fec67565fb88c8bcd3841b7090566d8fc12ccb70436b5269456e55c00"
      hash2 = "d2b612729d0c106cb5b0434e3d5de1a5dc9d065d276d51a3fb25a08f39e18467"
      hash3 = "ea7ed9bb14a7bda590cf3ff81c8c37703a028c4fdb4599b6a283d68fdcb2613f"
   strings:
      // Bonus : Doesn't count in the condition
      $s1 = "F:\\2-Sources\\21-FinalCobalt\\Source\\cobalt\\Cobalt\\Cobalt\\Win32\\Release\\Client\\Cobalt.Client.pdb" fullword ascii
      $s2 = ".\\Cobalt-Client-log.txt" fullword ascii
      $s3 = ".\\Config.ini" fullword wide
      $s4 = "Local\\{C15730E2-145C-4c5e-B005-3BC753F42475}-once-flag" fullword ascii
      // Change the wallpaper
      $s5 = "\\Microsoft\\Windows\\Themes\\TranscodedWallpaper" fullword ascii
      // ping localhost
      $s6 =  { 40 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 20 00 70 00 69 00 6e 00 67 00 20 00 31 00 2e 00 31 00 2e 00 31 00 2e 00 31 00 20 00 2d 00 6e 00 20 00 31 00 20 00 2d 00 77 00 20 00 33 00 30 00 30 00 30 00 20 00 3e 00 20 00 4e 00 75 00 6c 00 20 00 26 00 20 00 44 00 65 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 71 00 20 00 22 00 25 00 73 00 22 } // @cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q "%s"
      $s7 = "%WINDRIVE%" fullword wide
      $s8 = "%WINDIR%" fullword wide
      $dbg1 = "message.txt" fullword ascii
      $dbg2 = "Failed To Get Data...." fullword ascii
      $dbg3 = "lock.locked()" fullword wide
      $dbg4 = { 47 65 74 41 64 61 70 74 65 72 73 49 6e 66 6f 20 66 61 69 6c 65 64 20 77 69 74 68 20 65 72 72 6f 72 3a 20 25 64 0a } // GetAdaptersInfo failed with error: %d\n
      $dbg5 = { 43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 20 66 61 69 6c 65 64 3a 20 25 78 0a } // CryptAcquireContext failed: %x\n
      $dbg6 = { 43 72 79 70 74 44 65 72 69 76 65 4b 65 79 20 66 61 69 6c 65 64 3a 20 25 78 0a 00 00 25 00 64 } // CryptDeriveKey failed: %x\n
      $dbg7 = { 5b 2d 5d 20 43 72 79 70 74 45 6e 63 72 79 70 74 20 66 61 69 6c 65 64 0a } // [-] CryptEncrypt failed\n
   condition:
      uint16(0) == 0x5a4d and filesize > 500KB and (5 of ($s*) and 4 of ($dbg*))
}
