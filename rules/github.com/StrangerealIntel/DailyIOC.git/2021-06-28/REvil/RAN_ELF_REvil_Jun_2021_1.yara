rule RAN_ELF_REvil_Jun_2021_1 {
   meta:
        description = "Detect the ELF version of REvil ransomware"
        author = "Arkbird_SOLG"
        reference1 = "https://twitter.com/VK_Intel/status/1409601311092490248"
        reference2 = "https://twitter.com/jaimeblascob/status/1409603887871500288"
        // add ref -> https://otx.alienvault.com/pulse/60da2c80aa5400db8f1561d5
        date = "2021-06-28"
        hash1 = "3d375d0ead2b63168de86ca2649360d9dcff75b3e0ffa2cf1e50816ec92b3b7d"
        hash2 = "d6762eff16452434ac1acc127f082906cc1ae5b0ff026d0d4fe725711db47763"
        hash3 = "796800face046765bd79f267c56a6c93ee2800b76d7f38ad96e5acb92599fcd4"
        hash4 = "ea1872b2835128e3cb49a0bc27e4727ca33c4e6eba1e80422db19b505f965bc4"
        tlp = "White"
        adversary = "RAAS"
   strings:
        $seq1 = { 55 48 89 e5 48 83 c4 80 bf 04 20 00 00 e8 69 d5 ff ff 48 89 45 f8 ?? 8b 05 [2] 31 00 [0-4] 48 8b 3d [2] 31 00 48 8b 35 [2] 31 00 48 8b 0d [2] 31 00 4c 8b 0d [2] 31 00 4c 8b [2] 13 31 00 48 8b 15 ?? 13 31 00 48 8b 45 f8 4c 89 ?? 24 18 48 89 7c 24 10 48 89 74 24 08 48 89 0c 24 ?? 89 }
        $seq2 = { 48 89 e5 bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff 8b 05 [2] 20 00 89 c6 bf [2] 41 00 b8 00 00 00 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff bf [2] 41 00 e8 [2] ff ff }
        $seq3 = { 48 83 ec 20 c7 45 fc 00 00 00 00 eb 64 8b 45 fc 48 8b 14 c5 48 92 61 00 48 8b 05 ?? bd 20 00 48 89 c6 bf 40 93 61 00 b8 00 00 00 00 e8 ?? 3f ff ff 8b 45 fc 48 8b 04 c5 48 92 61 00 48 89 c6 bf [2] 41 00 b8 00 00 00 00 e8 ?? 3d ff ff be [2] 41 00 bf 40 93 61 00 e8 ?? 3e ff ff 48 89 45 f0 48 8b 45 f0 48 89 c7 e8 ?? 3d ff ff 83 45 fc 01 83 7d fc 00 74 96 48 8b 05 [2] 20 00 48 89 c7 e8 ?? 3c ff ff 48 8b 05 [2] 20 00 be [2] 41 00 48 89 c7 e8 ?? 3e ff ff 48 89 45 e8 48 8b 45 e8 48 89 c7 e8 ?? 3d ff ff c9 c3 55 48 89 e5 48 83 ec 20 48 89 7d e8 48 8b 45 e8 48 89 c7 e8 ?? 3c ff ff 89 c2 8b 05 ?? d0 30 00 01 d0 83 c0 01 89 c7 e8 ?? 91 ff ff 48 89 45 f8 48 8b 55 e8 48 8b 45 f8 48 89 d6 48 89 c7 e8 ?? 3c ff ff 48 8b 45 f8 48 c7 c1 ff ff ff ff 48 89 c2 b8 00 00 00 00 48 89 d7 f2 ae 48 89 c8 48 f7 d0 48 8d 50 ff 48 8b 45 f8 48 01 d0 66 c7 00 2f 00 48 8b 15 ?? cf 30 00 48 8b 45 f8 48 89 d6 48 89 c7 e8 ?? 3e ff ff 48 8b 45 f8 be [2] 41 00 48 89 c7 e8 ?? 3e ff ff 48 89 45 f0 48 83 7d f0 00 }
        $seq4 = { 48 89 e5 48 83 ec 10 c7 45 fc 58 00 00 00 8b 45 fc 48 8d 55 f0 48 89 c6 bf 00 a5 71 00 e8 [2] 00 00 48 89 05 ?? 0b 31 00 48 8d 45 f0 48 89 c2 be 20 00 00 00 bf c0 a4 71 00 e8 [2] 00 00 48 89 05 [2] 31 00 b8 00 00 00 00 e8 b7 fd ff ff 48 89 05 [2] 31 00 48 8b 05 [2] 31 00 48 85 c0 74 09 48 8b 05 [2] 31 00 eb 05 b8 [2] 41 00 48 89 05 [2] 31 00 b8 00 00 00 00 e8 80 fe ff ff 48 89 05 [2] 31 00 48 8b 05 [2] 31 00 48 85 c0 74 09 48 8b 05 [2] 31 00 eb 05 b8 [2] 41 00 48 89 05 ?? 0a 31 00 48 c7 05 ?? 0a 31 00 [2] 41 00 e8 ?? f6 ff ff e8 f1 f7 ff ff b8 01 00 00 00 }
   condition:
       uint32(0) == 0x464c457f and filesize > 50KB and 3 of ($seq*)
}
