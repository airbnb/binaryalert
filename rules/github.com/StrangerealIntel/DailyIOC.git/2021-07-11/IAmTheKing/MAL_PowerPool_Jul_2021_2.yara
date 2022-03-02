rule MAL_PowerPool_Jul_2021_2 {
   meta:
        description = "Detect PowerPool malware (ALPC exploit variant)"
        author = "Arkbird_SOLG"
        reference = "https://www.welivesecurity.com/2018/09/05/powerpool-malware-exploits-zero-day-vulnerability/"
        date = "2021-07-09"
        // Build 2017
        hash1 = "035f97af0def906fbd8f7f15fb8107a9e852a69160669e7c0781888180cd46d5"
        hash2 = "a72cdb6be7a967d3aa0021d2331b61af84455539e6f127720c9aac9b8392ec24"
        //Build 2018
        hash3 = "df7b9d972ac83cc4a590f09d74cb242de3442cc9c1f19ed08f62bd6ebc9fc0fd"
        tlp = "White"
        adversary = "IAmTheKing"
   strings:
        $s1 = { 5c 00 53 00 74 00 72 00 69 00 6e 00 67 00 46 00 69 00 6c 00 65 00 49 00 6e 00 66 00 6f 00 5c 00 25 00 30 00 34 00 78 00 25 00 30 00 34 00 78 00 5c 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e }
        $s2 = { 2f 00 3f 00 69 00 64 00 3d 00 25 00 73 00 26 00 69 00 6e 00 66 00 6f 00 3d 00 25 00 73 }
        $s3 = { 72 00 61 00 72 00 2e 00 65 00 78 00 65 00 20 00 61 00 20 00 2d 00 72 00 20 00 25 00 73 00 2e 00 72 00 61 00 72 00 20 00 2d 00 74 00 61 00 25 00 30 00 34 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 20 00 2d 00 74 00 62 00 25 00 30 00 34 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 }
        $s4 = { 63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 24 00 50 00 53 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 54 00 61 00 62 00 6c 00 65 00 2e 00 50 00 53 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 3e 00 20 00 22 00 25 00 73 00 22 }
        $s5 = { 63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 22 00 25 00 73 00 22 00 20 00 3e 00 20 00 22 00 25 00 73 00 22 }
        $s6 = { 83 c4 04 53 56 68 [2] 42 00 ba c8 ?? 43 00 e8 ?? a9 ff ff 83 c4 0c 56 68 [2] 42 00 ba c8 ?? 43 00 e8 ?? a9 ff ff 83 c4 08 83 7c 24 20 00 68 40 01 00 00 74 61 33 ed 55 68 88 ?? 43 00 e8 ?? a4 00 00 b8 50 ?? 42 00 83 c4 0c 8b d0 66 8b 08 83 c0 02 66 3b cd 75 f5 bf 88 ?? 43 00 2b c2 83 c7 fe 8d 64 24 00 66 8b 4f 02 83 c7 02 66 3b cd 75 f4 8b c8 c1 e9 02 8b f2 f3 a5 8b c8 83 e1 03 68 90 ?? 42 00 f3 a4 e8 [2] 00 00 83 c4 04 33 f6 89 74 24 20 eb 66 6a 00 68 88 ?? 43 00 e8 ?? a4 00 00 b8 f0 ?? 42 00 83 c4 0c 8b d0 66 8b 08 83 c0 02 66 85 c9 75 f5 bf 88 ?? 43 00 2b c2 83 c7 fe 8d 64 24 00 66 8b 4f 02 83 c7 02 66 85 c9 75 f4 8b c8 c1 e9 02 8b f2 f3 a5 8b c8 83 e1 03 68 98 ?? 42 00 f3 a4 e8 ?? 95 00 00 c7 44 24 24 01 00 00 00 8b 74 24 24 83 c4 04 33 ed 68 d0 07 00 00 a3 d4 ?? 42 00 }
   condition:
     uint16(0) == 0x5a4d and filesize > 100KB and 5 of ($s*)
}
