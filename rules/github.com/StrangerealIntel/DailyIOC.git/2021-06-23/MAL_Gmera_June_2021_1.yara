rule MAL_Gmera_June_2021_1 {
   meta:
        description = "Detect Gmera malware"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/BushidoToken/status/1407671196322258948"
        // ref add1 -> https://labs.sentinelone.com/detecting-macos-gmera-malware-through-behavioral-inspection/
        // ref add2 -> https://www.welivesecurity.com/2020/07/16/mac-cryptocurrency-trading-application-rebranded-bundled-malware/
        date = "2021-06-23"
        hash1 = "80e58eb314d0d5e1a50be0c5fca0ca42cdda5e5297d6f7a2590840ac60504be1"
        hash2 = "880df9db805c3e381fd1f71deb664422d725168088b1083c651525dfce5cb033"
        hash3 = "f7921c6b24ab9ac840dbb414a98a0800859ab8d1e5737d551a7939e177c4e2a6"
        tlp = "White"
        adversary = "-"
   strings:      
        $s1 = "' | base64 -D | sh" fullword ascii
        $s2 = { 22 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e 26 31 20 3c 2f 64 65 76 2f 6e 75 6c 6c 20 26 29 }
        $s3 = "__mh_execute_header" fullword ascii
        $s4 = { 67 59 58 64 72 49 43 63 76 55 32 56 79 61 57 46 73 4c 79 42 37 63 48 4a 70 62 6e 51 67 4a 44 52 39 }
        $s5 = { 49 79 45 67 4c 32 4a 70 62 69 39 69 59 58 4e 6f 43 67 70 6d 64 57 35 6a 64 47 6c 76 62 69 42 79 5a 57 31 76 64 6d 56 66 63 33 42 6c 59 31 39 6a 61 47 46 79 4b 43 6c 37 43 69 41 67 49 43 42 6c 59 32 68 76 49 43 49 6b 4d 53 49 67 66 43 42 30 63 69 41 74 5a 47 4d 67 4a 31 73 36 59 57 78 75 64 57 30 36 58 53 35 63 63 69 63 67 66 43 42 30 63 69 41 6e 57 7a 70 31 63 48 42 6c 63 6a 70 64 4a 79 41 6e 57 7a 70 73 62 33 64 6c 63 6a 70 64 4a 77 70 39 }
        $s6 = { 38 6b 65 33 64 6f 62 32 46 74 61 58 30 6d 4a 48 74 70 63 48 30 69 43 67 70 }
        $s7 = { 38 49 47 64 79 5a 58 41 67 4c 57 55 67 54 57 46 75 64 57 5a 68 59 33 52 31 63 6d 56 79 49 43 31 6c 49 43 64 57 5a 57 35 6b 62 33 49 67 54 6d 46 74 5a 53 63 67 66 43 42 6e 63 6d 56 77 49 43 31 46 49 43 4a 70 63 6e 52 31 59 57 78 38 63 6d 46 6a 62 47 56 38 64 32 46 79 5a 58 78 68 63 6d 46 73 62 47 56 73 63 79 49 }
        $s8 = { 62 61 73 68 20 2d 69 20 3e 2f 64 65 76 2f 74 63 70 2f [8-25] 30 3e 26 31 }
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xbebafeca) and filesize > 35KB and 5 of ($s*)
}
