rule WIP_Unk_Wiper_July_2021_1 {
   meta:
        description = "Detect unknown wiper that focuses olympic games in Japan"
        author = "Arkbird_SOLG"
        reference = "https://www.mbsd.jp/research/20210721/blog/"
        date = "2021-07-22"
        hash1 = "295d0aa4bf13befebafd7f5717e7e4b3b41a2de5ef5123ee699d38745f39ca4f" // unpacked sample
        hash2 = "511fee839098dfa28dd859ffd3ece5148be13bfb83baa807ed7cac2200103390" // packed UPX sample
        tlp = "green"
        adversary = "Olympic Destroyer ?"
   strings:      
            $s1 = "\\\\.\\Global\\ProcmonDebugLogger" fullword ascii
            $s2 = { 50 52 4f 43 4d 4f 4e 5f 57 49 4e 44 4f 57 5f 43 4c 41 53 53 00 00 00 00 4f 6c 6c 79 44 62 67 }
            $s3 = { 8d 44 24 10 50 ff 15 08 30 40 00 50 ff 15 2c 30 40 00 83 7c 24 10 00 0f 85 76 02 00 00 33 c9 0f 1f }
            $s4 = { 50 68 00 12 40 00 ff 15 60 30 40 00 85 c0 0f 85 ef 02 00 00 50 68 80 00 00 00 6a 03 50 6a 07 68 00 00 00 80 68 0c 32 40 00 ff 15 18 30 40 00 83 }
            $s5 = { 8b 3d d0 30 40 00 88 84 0c e8 00 00 00 8d 84 24 e8 00 00 00 50 ff d7 83 c4 04 b0 9a 33 c9 0f 1f 00 f6 d0 88 84 0c b4 00 00 00 41 8a 81 30 32 40 }
            $s6 = { 8b ec 83 ec 14 83 65 f4 00 8d 45 f4 83 65 f8 00 50 ff 15 34 30 40 00 8b 45 f8 33 45 f4 89 45 fc ff 15 38 30 40 00 31 45 fc ff 15 3c 30 40 00 31 45 fc 8d 45 ec 50 ff 15 40 30 40 00 8b 45 f0 8d 4d fc 33 45 ec 33 45 fc 33 }
            $p1 = { 5c 2e 5c 47 6c 6f 62 61 6c 5c 35 84 44 65 62 75 67 4c 6f 67 67 3f }
            $p2 = "UPX" fullword ascii
            $p3 = { 45 6e 75 6d 57 69 6e 64 6f 77 73 }
            $p4 = { 73 65 74 5f 6e 65 77 5f 6d 6f 64 65 00 00 00 5f 63 6f 6e 66 69 67 74 68 72 65 61 64 6c 6f 63 61 6c 65 }
            $p5 = { 4e 75 74 6f 72 75 6e 2f 43 4e 65 74 }
            $p6 = { 44 50 52 4f 43 4d 4f 4e 5f 57 49 4e 44 4f 57 5f 43 4c 41 53 53 }
            $p7 = { 53 6d 61 72 74 53 6e 69 66 66 67 }
            $p8 = { 26 30 30 63 66 67 }
            $p9 = { 72 6f 63 65 94 48 61 63 6b }
    condition:
            uint16(0) == 0x5a4d and filesize > 200KB and ( 5 of ($s*) or 7 of ($p*) )
}
