import "pe" 

rule APT_Patchwork_Tool_CVE_2019_0808_1 {
   meta:
      description = "Detect CVE 2019-0808 tool used by Patchwork group"
      author = "Arkbird_SOLG"
      reference = "https://blog.exodusintel.com/2019/05/17/windows-within-windows/"
      date = "2020-08-27"
      hash1 = "49f8a9203e5055777a67490923243405b9aa519016645fd75731c53cbf02073c"
      level = "Experimental"
   strings:
      $asm1 = { 8b 3d 44 21 01 10 6a 00 6a 00 6a 01 6a 01 6a 00 6a 00 68 00 00 00 08 68 e4 7e 01 10 68 e8 7e 01 10 6a 00 ff d7 50 68 f0 7e 01 10 a3 c8 a2 01 10 e8 e8 f7 ff ff 8b 35 68 21 01 10 8d 84 24 5c 01 00 00 83 c4 08 c7 84 24 54 01 00 00 1c 00 00 00 0f 57 c0 c7 84 24 58 01 00 00 10 00 00 00 66 0f 13 84 24 60 01 00 00 66 0f 13 84 24 68 01 00 00 50 ff b4 24 1c 01 00 00 c7 84 24 64 01 00 00 00 00 00 60 ff d6 8d 84 24 54 01 00 00 50 ff 74 24 10 ff d6 8b 35 5c 21 01 10 68 04 7f 01 10 ff 74 24 10 68 10 04 00 00 ff b4 24 24 01 00 00 ff } // Seq CreateWindow -> hWndMain
      $asm2 = { a1 14 21 01 10 0f 57 c0 8b 74 24 08 89 84 24 28 01 00 00 8d 84 24 20 01 00 00 50 c7 84 24 28 01 00 00 00 00 00 00 66 0f 13 84 24 3c 01 00 00 c7 84 24 44 01 00 00 00 00 00 00 c7 84 24 50 01 00 00 00 00 00 00 c7 84 24 24 01 00 00 30 00 00 00 c7 84 24 30 01 00 00 00 00 00 00 c7 84 24 34 01 00 00 00 00 00 00 89 b4 24 38 01 00 00 c7 84 24 48 01 00 00 00 00 00 00 c7 84 24 4c 01 00 00 10 7f 01 10 ff 15 64 21 01 10 6a 00 56 6a 00 6a 00 6a 01 6a 01 6a 00 6a 00 68 00 00 00 08 68 20 7f 01 10 68 10 7f 01 10 6a 00 ff d7 6a 00 50 6a 00 6a 00 a3 ec a2 01 10 6a 00 ff b4 24 2c 01 00 00 ff 15 58 21 01 } // Register Main Class
      $asm3 = { e8 72 fb ff ff 83 c4 08 68 c0 13 00 10 6a fc ff 76 0c ff 15 54 21 01 10 56 ff 75 0c ff 75 08 6a 00 ff 15 24 21 01 10 5f 5e 5b 5d } // Set window and hook it  
      $s1 = "[*] Successfully exploited CVE-2019-0808 and triggered the shellcode!" fullword ascii
      $s2 = "[!] Failed to find the address of IsMenu within user32.dll." fullword ascii
      $s3 = "Sending hSecondaryWindow a WM_ENTERIDLE message to trigger the execution of the shellcode as SYSTEM." fullword ascii
      $s4 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s5 = "[*] Found target windows!" fullword ascii
      $s6 = "[*] addressOfIsMenuFromStartOfUser32: 0x%08X" fullword ascii
      $s7 = "[*] FakeMenu: %p" fullword ascii
      $s8 = "[*] Primary window address: 0x%08X" fullword ascii
      $s9 = "[!] Didn't exploit the program. For some reason our privileges were not appropriate." fullword ascii
      $s10 = "[*] hUser32: 0x%08X" fullword ascii
      $s11 = "[*] Secondary window address: 0x%08X" fullword ascii
      $s12 = "[*] Offset: 0x%08X" fullword ascii
      $s13 = "[*] pHmValidateHandle: 0x%08X" fullword ascii
      $s14 = "[*] HWND: %p " fullword ascii
      $s15 = "[*] pIsMenuFunction: 0x%08X" fullword ascii
      $s16 = "[*] Destroyed spare windows!" fullword ascii
      $s17 = "[!] SetWindowLongA malicious error: 0x%08X" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize > 70KB and ( pe.imphash() == "d4a5e8c255211639195793920eeda70f" and 2 of ($asm*) and 12 of ($s*) )
}
