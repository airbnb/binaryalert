rule APT_Tardigrade_Nov_2021_1 {
    meta:
        description = "Detect Tardigrade loader"
        author = "Arkbird_SOLG"
        reference ="https://www.isac.bio/post/tardigrade"
        date = "2021-11-22"
        hash1 = "1c7c1a28921d81f672320e81ad58642ef3b8e27abf8a8e51400b98b40f49568be"
        hash2 = "c0976a1fbc3dd938f1d2996a888d0b3a516b432a2c38d788831553d81e2f5858"
        hash3 = "cf88926b7d5a5ebbd563d0241aaf83718b77cec56da66bdf234295cc5a91c5fe"
        tlp = "white"
        adversary = "Tardigrade"
    strings:
        $s1 = { 63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f 20 [10-40] 3e 22 25 73 22 26 65 78 69 74 }
        $s2 = { 4c 89 44 24 38 89 54 24 34 48 89 4c 24 28 e8 [2] 01 00 e8 [2] 01 00 4c 8b 44 24 38 8b 54 24 34 48 8b 4c 24 28 48 83 c4 48 e9 71 fe ff ff 90 48 89 ca 48 8d 0d 76 ?? 02 00 }
        $s3 = { 41 57 41 56 41 55 41 54 55 57 56 53 48 ?? ec [1-4] 48 8b 84 24 ?? 00 00 00 48 89 44 24 60 48 8b 05 [2] 01 00 48 89 4c 24 40 ?? 38 }
        $s4 = { 45 31 c0 48 8d 8c 24 ?? 02 00 00 4c 8d 8c 24 ?? 01 00 00 48 8d 15 [2] 01 00 ff 15 [2] 02 00 }
   condition:
        uint16(0) == 0x5a4d and filesize > 50KB and all of them
}
