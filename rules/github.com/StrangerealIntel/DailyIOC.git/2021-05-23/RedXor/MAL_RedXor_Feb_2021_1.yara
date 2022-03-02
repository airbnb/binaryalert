rule MAL_RedXor_Feb_2021_1 {
   meta:
        description = "Detect RedXor backdoor (Feb 2021)"
        author = "Arkbird_SOLG"
        reference = "https://www.intezer.com/blog/malware-analysis/new-linux-backdoor-redxor-likely-operated-by-chinese-nation-state-actor/"
        date = "2021-03-14"
        hash1 = "0423258b94e8a9af58ad63ea493818618de2d8c60cf75ec7980edcaa34dcc919"
        hash2 = "0a76c55fa88d4c134012a5136c09fb938b4be88a382f88bf2804043253b0559"
        tlp = "White"
        adversary = "Winnti"
   strings:      
        $seq1 = { 0f b7 05 [2] 20 00 66 85 c0 0f 85 cd 00 00 00 48 8d 85 ?? ff ff ff be 10 00 00 00 48 89 c7 e8 [2] ff ff 66 c7 85 ?? ff ff ff 02 00 0f b7 05 [2] 20 00 0f b7 c0 89 c7 e8 [2] ff ff 66 89 85 ?? ff ff ff 48 8b 45 d8 48 89 c7 e8 [2] ff ff 89 85 ?? ff ff ff ba 00 00 00 00 be 01 00 00 00 bf 02 00 00 00 e8 [2] ff ff 89 85 ?? ff ff ff 83 bd ?? ff ff ff ff 75 21 8b 85 ?? ff ff ff 89 c7 e8 [2] ff ff bf 0a 00 00 00 e8 [2] ff ff b8 00 00 00 }
        $seq2 = { 48 8d 8d ?? ff ff ff 8b 85 ?? ff ff ff ba 10 00 00 00 48 89 ce 89 c7 e8 [2] ff ff 83 f8 ff 75 47 8b 85 ?? ff ff ff 89 c7 e8 [2] ff ff bf 0a 00 00 00 e8 [2] ff ff b8 00 00 00 }
        $seq3 = { 48 8d 85 [2] fd ff be 00 10 00 00 48 89 c7 e8 [2] ff ff b9 [2] 40 00 48 8b 95 [2] fd ff 48 8d 85 [2] fd ff 48 89 ce 48 89 c7 b8 00 00 00 00 e8 [2] ff ff 48 8d 85 [2] fd ff 48 89 c7 e8 [2] ff ff 89 85 30 ff ff ff 8b 85 30 ff ff ff 48 63 d8 8b 85 30 ff ff ff 48 63 c8 48 8d 95 [2] fd ff 48 8d 85 [2] fe ff 49 89 d8 be [2] 40 00 48 89 c7 e8 [2] ff ff 89 85 2c ff ff ff 8b 85 2c ff ff ff 48 63 d0 48 8d 9d [2] fe ff 8b 85 ?? ff ff ff b9 00 00 00 00 48 89 de 89 c7 e8 [2] ff ff 48 83 f8 ff 75 21 8b 85 ?? ff ff ff 89 c7 e8 [2] ff ff bf 0a 00 00 00 e8 [2] ff ff b8 00 00 00 }
        $seq4 = { c7 45 a8 01 00 00 00 c7 45 ac 01 00 00 00 c7 05 [2] 20 00 00 00 00 00 48 8d 85 [2] fd ff be 00 10 00 00 48 89 c7 e8 [2] ff ff b9 [2] 40 00 48 8d 85 [2] fd ff ba ?? 00 00 00 48 89 ce 48 89 c7 e8 [2] ff ff 48 8d 85 [2] fd ff 48 89 c7 e8 [2] ff ff 48 89 c2 8b 85 ?? ce fd ff 48 8d 8d [2] fd ff 48 89 ce 89 c7 e8 [2] ff ff 48 8d 85 [2] fd ff be 00 10 00 00 48 89 c7 e8 [2] ff ff 8b 85 ?? ce fd ff 48 8d 8d [2] fd ff ba ff 0f 00 00 48 89 ce 89 c7 e8 [2] ff ff 89 85 40 ff ff ff 83 bd 40 ff ff ff ff 75 0a c7 85 40 ff ff ff 00 00 00 00 48 8d 85 [2] fd ff be [2] 40 00 48 89 c7 e8 [2] ff ff 48 85 c0 0f 84 d0 00 00 00 48 8d 85 [2] fd ff be 00 10 00 00 48 89 c7 e8 [2] ff ff b9 [2] 40 00 48 8d 85 [2] fd ff ba 02 00 00 00 48 89 ce 48 89 c7 e8 [2] ff ff e8 [2] ff ff 89 c7 e8 [2] ff ff 48 89 45 e8 be 00 02 00 00 bf [2] 60 00 e8 [2] ff ff 48 8b 45 e8 48 8b 00 48 89 c6 bf [2] 60 00 e8 [2] ff ff be 00 02 00 00 bf [2] 60 00 e8 [2] ff ff be 00 02 00 00 bf [2] 60 00 e8 [2] ff ff bb [2] 40 00 48 8d 95 [2] fd ff 48 8d 85 [2] fd ff 41 b8 [2] 60 00 48 89 d1 ba [2] 60 00 48 89 de 48 89 c7 b8 00 00 00 00 e8 [2] ff ff 48 8d 85 [2] fd ff 48 89 c7 e8 [2] ff ff 89 85 30 ff ff ff c7 45 ac 00 00 00 }
        $seq5 = { 55 48 89 e5 53 89 fb 89 f0 48 89 55 d8 89 4d d4 88 5d e4 88 45 e0 0f b6 45 e4 88 45 f2 0f b6 45 e0 88 45 f3 c7 45 f4 00 00 00 00 c7 45 f4 00 00 00 00 eb 29 8b 45 f4 48 98 48 03 45 d8 8b 55 f4 48 63 d2 48 03 55 d8 0f b6 0a 0f b6 55 f2 31 ca 88 10 0f b6 45 f3 00 45 f2 83 45 f4 01 8b 45 f4 3b 45 d4 7c cf b8 00 00 00 00 5b }
        $seq6 = { 55 48 89 e5 53 48 81 ec 68 0d 00 00 48 89 bd d8 f2 ff ff c7 45 90 31 32 37 2e c7 45 94 30 2e 30 2e 48 c7 45 98 31 00 00 00 c7 45 a0 00 00 00 00 c7 85 70 ff ff ff 30 30 2d 30 c7 85 74 ff ff ff 30 2d 30 30 c7 85 78 ff ff ff 2d 30 30 2d c7 85 7c ff ff ff 30 30 2d 30 c7 45 80 30 00 00 00 48 c7 45 a8 [2] 40 00 }
    condition:
        uint32(0) == 0x464c457f  and filesize > 25KB and all of ($seq*)
}
