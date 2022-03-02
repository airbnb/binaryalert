import "pe"

rule shadowspawn_utility {

   meta:

      description = "Rule to detect ShadowSpawn utility used in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-06-25"
      rule_version = "v1"
      malware_type = "utility"
      malware_family = "Trojan:W32/ShadowSpawn"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
      

   strings:

      $pdb = "C:\\data\\projects\\shadowspawn\\src\\bin\\Release-W2K3\\x64\\ShadowSpawn.pdb" fullword ascii

      $op0 = { e9 34 ea ff ff cc cc cc cc 48 8d 8a 20 }
      $op1 = { 48 8b 85 e0 06 00 00 48 8d 34 00 48 8d 46 02 48 }
      $op2 = { e9 34 c1 ff ff cc cc cc cc 48 8b 8a 68 }

   condition:

      uint16(0) == 0x5a4d and
      filesize < 200KB and
      ( pe.imphash() == "eaae87b11d2ebdd286af419682037b4c" and
      all of them)
}

rule poison_ivy_softcell {

   meta:

      description = "Rule to detect Poison Ivy used in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-06-25"
      rule_version = "v1"
      malware_type = "rat"
      malware_family = "Rat:W32/PoisonIvy"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"

   strings:

      $s1 = "Cannot create folder %sDCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s2 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide
      $s3 = "&Enter password for the encrypted file:" fullword wide
      $s4 = "start \"\" \"%CD%\\mcoemcpy.exe\"" fullword ascii
      $s5 = "setup.bat" fullword ascii
      $s6 = "ErroraErrors encountered while performing the operation" fullword wide
      $s7 = "Please download a fresh copy and retry the installation" fullword wide
      $s8 = "antivir.dat" fullword ascii
      $s9 = "The required volume is absent2The archive is either in unknown format or damaged" fullword wide
      $s10 = "=Total path and file name length must not exceed %d characters" fullword wide
      $s11 = "Please close all applications, reboot Windows and restart this installation\\Some installation files are corrupt." fullword wide

      $op0 = { e8 6f 12 00 00 84 c0 74 04 32 c0 eb 34 56 ff 75 }
      $op1 = { 53 68 b0 34 41 00 57 e8 61 44 00 00 57 e8 31 44 }
      $op2 = { 56 ff 75 08 8d b5 f4 ef ff ff e8 17 ff ff ff 8d }

   condition:

      uint16(0) == 0x5a4d and
      filesize < 500KB and
      ( pe.imphash() == "dbb1eb5c3476069287a73206929932fd" and
      all of them)
}

rule trochilus_softcell {

   meta:

      description = "Rule to detect Trochilus malware used in the SoftCell operation"
      date = "2019-06-25"
      rule_version = "v1"
      malware_type = "trojan"
      malware_family = "Trojan:W32/Trochilus"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"

   strings:

      $s1 = "Shell.dll" fullword ascii
      $s2 = "photo.dat" fullword wide
      $s3 = "VW9HxtV9H|tQ9" fullword ascii
      $s4 = "G6uEGRich7uEG" fullword ascii

      $op0 = { e8 9d ad ff ff ff b6 a8 }
      $op1 = { e8 d4 ad ff ff ff b6 94 }
      $op2 = { e8 ea ad ff ff ff b6 8c }

   condition:

      uint16(0) == 0x5a4d and
      filesize < 200KB and
      ( pe.imphash() == "8e13ebc144667958722686cb04ee16f8" and
      ( pe.exports("Entry") and
      pe.exports("Main") ) and
      all of them )
}

rule lg_utility_lateral_movement_softcell {

   meta:

      description = "Rule to detect the utility LG from Joeware to do Lateral Movement in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-06-25"
      rule_version = "v1"
      malware_type = "utility"
      malware_family = "Utility:W32/Joeware"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"

   strings:

      $s1 = "lg \\\\comp1\\users louise -add -r comp3" fullword ascii
      $s2 = "lg \\\\comp1\\users S-1-5-567-678-89765-456 -sid -add" fullword ascii
      $s3 = "lg \\\\comp1\\users -sidsout" fullword ascii
      $s4 = "Enumerates members of localgroup users on localhost" fullword ascii
      $s5 = "Adds SID resolved at comp3 for louise to localgroup users on comp1" fullword ascii
      $s6 = "CodeGear C++ - Copyright 2008 Embarcadero Technologies" fullword ascii
      $s7 = "Lists members of localgroup users on comp1 in SID format" fullword ascii
      $s8 = "ERROR: Verify that CSV lines are available in PIPE input. " fullword ascii

      $op0 = { 89 43 24 c6 85 6f ff ff ff 00 83 7b 24 10 72 05 }
      $op1 = { 68 f8 0e 43 00 e8 8d ff ff ff 83 c4 20 68 f8 0e }
      $op2 = { 66 c7 85 74 ff ff ff 0c 00 8d 55 d8 52 e8 e9 eb }

   condition:

      uint16(0) == 0x5a4d and
      filesize < 600KB and
      ( pe.imphash() == "327ce3f883a5b59e966b5d0e3a321156" and
      all of them )
}

rule mangzamel_softcell {

   meta:

      description = "Rule to detect Mangzamel used in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-06-25"
      rule_version = "v1"
      malware_type = "trojan"
      malware_family = "Trojan:W32/Mangzamel"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"

   strings:

      $s1 = "Change Service Mode to user logon failure.code:%d" fullword ascii
      $s2 = "spoolsvs.exe" fullword wide
      $s3 = "System\\CurrentControlSet\\Services\\%s\\parameters\\%s" fullword ascii
      $s4 = "Please Correct [-s %s]" fullword ascii
      $s5 = "Please Correct [-m %s]" fullword ascii

      $op0 = { 59 8d 85 64 ff ff ff 50 c7 85 64 ff ff ff 94 }
      $op1 = { c9 c2 08 00 81 c1 30 34 00 00 e9 cf 9b ff ff 55 }
      $op2 = { 80 0f b6 b5 68 ff ff ff c1 e2 04 0b d6 0f b6 b5 }

   condition:
      uint16(0) == 0x5a4d and
      filesize < 300KB and
      ( pe.imphash() == "ef64bb4aa42ef5a8a2e3858a636bce40" and
      all of them )
}

rule nbtscan_utility_softcell {

   meta:

      description = "Rule to detect nbtscan utility used in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-06-25"
      rule_version = "v1"
      malware_type = "utility"
      malware_family = "Utility:W32/NbtScan"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"

   strings:

      $s1 = "nbtscan 1.0.35 - 2008-04-08 - http://www.unixwiz.net/tools/" fullword ascii
      $s2 = "parse_target_cb.c" fullword ascii
      $s3 = "ranges. Ranges can be in /nbits notation (\"192.168.12.0/24\")" fullword ascii
      $s4 = "or with a range in the last octet (\"192.168.12.64-97\")" fullword ascii

      $op0 = { 52 68 d4 66 40 00 8b 85 58 ff ff ff 50 ff 15 a0 }
      $op1 = { e9 1c ff ff ff 8b 45 fc 8b e5 5d c3 cc cc cc cc }
      $op2 = { 59 59 c3 8b 65 e8 ff 75 d0 ff 15 34 60 40 00 ff }

   condition:

      uint16(0) == 0x5a4d and
      filesize < 100KB and
      ( pe.imphash() == "2fa43c5392ec7923ababced078c2f98d" and
      all of them )
}

rule mimikatz_utility_softcell {

   meta:

      description = "Rule to detect Mimikatz utility used in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-06-25"
      rule_version = "v1"
      malware_type = "hacktool"
      malware_family = "Hacktool:W32/Mimikatz"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"

   strings:

      $s1 = "livessp.dll" fullword wide 
      $s2 = "\\system32\\tapi32.dll" fullword wide
      $s3 = " * Process Token : " fullword wide
      $s4 = "lsadump" fullword wide
      $s5 = "-nl - skip lsa dump..." fullword wide
      $s6 = "lsadump::sam" fullword wide
      $s7 = "lsadump::lsa" fullword wide
      $s8 = "* NL$IterCount %u, %u real iter(s)" fullword wide
      $s9 = "* Iter to def (%d)" fullword wide
      $s10 = " * Thread Token  : " fullword wide
      $s11 = " * RootKey  : " fullword wide
      $s12 = "lsadump::cache" fullword wide
      $s13 = "sekurlsa::logonpasswords" fullword wide
      $s14 = "(commandline) # %s" fullword wide
      $s15 = ">>> %s of '%s' module failed : %08x" fullword wide
      $s16 = "UndefinedLogonType" fullword wide
      $s17 = " * Username : %wZ" fullword wide
      $s18 = "logonPasswords" fullword wide
      $s19 = "privilege::debug" fullword wide
      $s20 = "token::elevate" fullword wide

      $op0 = { e8 0b f5 00 00 90 39 35 30 c7 02 00 75 34 48 8b }
      $op1 = { eb 34 48 8b 4d cf 48 8d 45 c7 45 33 c9 48 89 44 }
      $op2 = { 48 3b 0d 34 26 01 00 74 05 e8 a9 31 ff ff 48 8b }

   condition:

      uint16(0) == 0x5a4d and
      filesize < 500KB and
      ( pe.imphash() == "169e02f00c6fb64587297444b6c41ff4" and
      all of them )
}

rule sfx_winrar_plugx {
   
   meta:

      description = "Rule to detect the SFX WinRAR delivering a possible Plugx sample"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-06-25"
      rule_version = "v1"
      malware_type = "builder"
      malware_family = "Builder:W32/Plugx"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"

   strings:

      $s1 = "Cannot create folder %sDCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s2 = "Wrong password for %s5Write error in the file %s. Probably the disk is full" fullword wide
      $s3 = "mcutil.dll" fullword ascii
      $s4 = "Unexpected end of archiveThe file \"%s\" header is corrupt%The archive comment header is corrupt" fullword wide
      $s5 = "mcoemcpy.exe" fullword ascii
      $s6 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide
      $s7 = "&Enter password for the encrypted file:" fullword wide
      $s8 = "start \"\" \"%CD%\\mcoemcpy.exe\"" fullword ascii
      $s9 = "setup.bat" fullword ascii
      $s10 = "ErroraErrors encountered while performing the operation" fullword wide
      $s11 = "Please download a fresh copy and retry the installation" fullword wide
      $s12 = "antivir.dat" fullword ascii
      $s13 = "The required volume is absent2The archive is either in unknown format or damaged" fullword wide
      $s14 = "=Total path and file name length must not exceed %d characters" fullword wide
      $s15 = "Please close all applications, reboot Windows and restart this installation\\Some installation files are corrupt." fullword wide
      $s16 = "folder is not accessiblelSome files could not be created." fullword wide
      $s17 = "Packed data CRC failed in %s" fullword wide
      $s18 = "DDTTDTTDTTDTTDTTDTTDTTDTTDTQ" fullword ascii
      $s19 = "File close error" fullword wide
      $s20 = "CRC failed in %s" fullword wide
      
      $op0 = { e8 6f 12 00 00 84 c0 74 04 32 c0 eb 34 56 ff 75 }
      $op1 = { 53 68 b0 34 41 00 57 e8 61 44 00 00 57 e8 31 44 }
      $op2 = { 56 ff 75 08 8d b5 f4 ef ff ff e8 17 ff ff ff 8d }

   condition:

      uint16(0) == 0x5a4d and 
      filesize < 500KB and
      ( pe.imphash() == "dbb1eb5c3476069287a73206929932fd" and
      all of them)
}

