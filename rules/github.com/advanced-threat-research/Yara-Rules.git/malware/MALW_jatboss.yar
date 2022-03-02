rule jatboss {
        
        meta:

            description = "Rule to detect PDF files from Jatboss campaign and MSG files that contained those attachents"
            author = "Marc Rivero | McAfee ATR Team"
            date = "2019-12-04"
            rule_version = "v1"
            malware_type = "phishing"
            malware_family = "Phishing:W32/Jatboss"
            actor_type = "Cybercrime"
            actor_group = "Unknown"
            reference = "https://exchange.xforce.ibmcloud.com/collection/JATBOSS-Phishing-Kit-17c74b38860de5cb9fc727e6c0b6d5b5"           
            hash = "b81fb37dc48812f6ad61984ecf2a8dbbfe581120257cb4becad5375a12e755bb"
            
        strings:

            //<</Author(JAT) /Creator( string    
            $jat = { 3C 3C 2F 41 75 74 68 6F 72 28 4A 41 54 29 20 2F 43 72 65 61 74 6F 72 28 }

          	//<</Author(jatboss) /Creator(
          	$jatboss = { 3C 3C 2F 41 75 74 68 6F 72 28 4A 41 54 29 20 2F 43 72 65 61 74 6F 72 28 }

          	//SPAM MSG file:
            $spam = { 54 00 68 00 69 00 73 00 20 00 65 00 2D 00 6D 00 61 00 69 00 6C 00 20 00 61 00 6E 00 64 00 20 00 61 00 6E 00 79 00 20 00 61 00 74 00 74 00 61 00 63 00 68 00 6D 00 65 00 6E 00 74 00 20 00 61 00 72 00 65 00 20 00 43 00 6F 00 6E 00 66 00 69 00 64 00 65 00 6E 00 74 00 69 00 61 00 6C 00 2E 00 }

      condition:

        	(uint16(0) == 0x5025 and
          filesize < 1000KB and
          ($jat or
          $jatboss)) or
          (uint16(0) == 0xcfd0 and 
          $spam and 
          any of ($jat*)) 
}
