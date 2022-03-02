rule MAL_QueenOfHearts_Jul_2021_1 {
   meta:
        description = "Detect QueenOfHearts malware"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/ShadowChasing1/status/1413111641504292864"
        date = "2021-07-09"
        hash1 = "44eb620879e0c3f80ff95fda5b1e301d471b59e47c4002132df646acfc7cc5ba"
        hash2 = "a63600e5c28a4c1770a53d310ff017abd3cb9c20cb58a85d53df0c06bcae1864"
        hash3 = "f110ebee387c2dfac08beb674a8efec20940bc562c5231e9bb4a90296476c29f"
        tlp = "White"
        adversary = "IAmTheKing"
   strings:
        $s1 = "send request error:%d" fullword ascii
        $s2 = "cookie size :%d" fullword wide
        $s3 = "querycode error" fullword wide
        $s4 = { 7b 27 73 65 73 73 69 6f 6e 27 3a 5b 7b 27 6e 61 6d 65 27 3a 27 [1-10] 27 2c 27 69 64 27 3a [1-6] 2c 27 74 69 6d 65 27 3a [3-10] 7d 5d 2c 27 6a 70 67 27 3a }
        $s5 = "PmMytex%d" fullword wide 
        $s6 = { 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 4c 00 65 00 6e 00 67 00 74 00 68 00 3a 00 20 00 25 00 49 00 36 00 34 00 75 00 0d 00 0a }
        $s7 = { 25 00 73 00 5c 00 25 00 73 00 2e 00 6c 00 6f 00 67 }
        $s8 = { 25 00 73 00 5f 00 25 00 63 00 25 00 63 00 25 00 63 00 25 00 63 00 5f 00 25 00 64 }
   condition:
     uint16(0) == 0x5a4d and filesize > 100KB and 5 of ($s*)
}
