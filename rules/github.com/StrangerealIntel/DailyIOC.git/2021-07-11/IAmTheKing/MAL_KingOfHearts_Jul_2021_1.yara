rule MAL_KingOfHearts_Jul_2021_1 {
   meta:
        description = "Detect KingOfHearts malware"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/ShadowChasing1/status/1413111641504292864"
        date = "2021-07-09"
        hash1 = "0639e8f5e517c3f57d28bfd9f51cabfb275c64b7bca224656c2ac04f5a8c3af0"
        hash2 = "0340a90ed4000e579c29f6ad7d4ab2ae1d30f18a2e777689e3e576862efbd6e0"
        hash3 = "393ccb9853ea7628792e4dd982c2dd52dd8f768fdb7b80b20cbfc2fac4e298a4"
        tlp = "White"
        adversary = "IAmTheKing"
   strings:
        $s1 = { 43 00 72 00 65 00 61 00 74 00 65 00 44 00 6f 00 77 00 6e 00 4c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 20 00 22 00 25 00 73 00 22 00 20 00 46 00 61 00 69 00 6c 00 65 00 64 00 2c 00 45 00 72 00 72 00 6f 00 72 00 3d 00 25 00 64 }
        $s2 = { 43 00 72 00 65 00 61 00 74 00 65 00 55 00 70 00 4c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 20 00 22 00 25 00 73 00 22 }
        $s3 = "HARDWARE\\DESCRIPTION\\System\\BIOS" fullword ascii
        $s4 = "\\1-driver-vmsrvc" fullword ascii
        $s5 = { 73 74 61 72 74 20 64 6f 77 6e 3a 20 25 73 0a }
        $s6 = { 66 00 69 00 6c 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 20 00 22 00 25 00 73 00 22 }
   condition:
     uint16(0) == 0x5a4d and filesize > 35KB and 4 of ($s*)
}
