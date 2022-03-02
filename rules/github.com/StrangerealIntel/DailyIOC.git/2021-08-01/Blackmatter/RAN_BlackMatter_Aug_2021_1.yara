rule RAN_BlackMatter_Aug_2021_1
{
    meta:
        description = "Detect BlackMatter ransomware"
        author = "Arkbird_SOLG"
        date = "2021-08-02"
        reference = "https://twitter.com/abuse_ch/status/1421834305416933376"
        hash1 = "22d7d67c3af10b1a37f277ebabe2d1eb4fd25afbd6437d4377400e148bcc08d6"
        hash2 = "7f6dd0ca03f04b64024e86a72a6d7cfab6abccc2173b85896fc4b431990a5984"
        level = "Experimental"
        tlp = "white"
        adversary = "-"
    strings:
        $s1 = { 55 8b ec 81 ec ac 02 00 00 53 51 52 56 57 c7 45 fc 00 00 00 00 c7 45 f4 00 00 00 00 c7 45 f0 00 00 00 00 c7 45 ec 00 00 00 00 6a 00 ff 15 00 15 41 00 85 c0 0f 85 3e 04 00 00 8d 45 d4 50 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 84 15 41 00 85 c0 0f 85 1c 04 00 00 8d 85 7c ff ff ff c7 00 b1 5f 5a 22 c7 40 04 c8 5f 75 22 c7 40 08 b1 5f 06 22 b9 03 00 00 00 81 30 ed 5f 06 22 83 c0 04 49 75 f4 8b 7d 08 8b 4d d4 8d 45 f8 50 6a 00 6a 00 6a 00 6a 00 6a 02 ff 71 1c ff 15 88 15 41 00 85 c0 75 6d 8d 45 dc 50 6a 00 6a 00 ff 75 f8 ff 15 8c 15 41 00 85 }
        $s2 = { 8d 45 88 c7 00 a1 5f 42 22 c7 40 04 ac 5f 56 22 c7 40 08 d7 5f 29 22 c7 40 0c c2 5f 45 22 c7 40 10 a3 5f 3b 22 c7 40 14 ae 5f 69 22 c7 40 18 80 5f 76 22 c7 40 1c 98 5f 72 22 c7 40 20 88 5f 74 22 c7 40 24 9e 5f 2a 22 c7 40 28 ed 5f 06 22 b9 0b 00 00 00 81 30 ed 5f 06 22 83 c0 04 49 75 f4 8d 45 88 50 8d 85 54 fd ff ff 50 ff 15 dc 12 41 00 83 c4 08 ff 75 cc 8d 85 54 fd ff ff 50 ff 15 d8 12 41 00 83 c4 08 8d 45 ec 50 8d 85 5c ff ff ff 50 6a 01 6a 00 6a 00 8d 85 54 fd ff ff 50 ff 15 98 15 41 00 }
        $s3 = { 8d 45 b4 c7 00 21 0a 83 e9 c7 40 04 c5 ce d7 33 c7 40 08 40 c4 06 e2 c7 40 0c a2 87 fb dd b9 04 00 00 00 81 30 ed 5f 06 22 83 c0 04 49 75 f4 8d 45 a4 c7 00 6a f9 14 fe c7 40 04 92 2c c9 33 c7 40 08 65 12 06 88 c7 40 0c ed 14 28 06 b9 04 00 00 00 81 30 ed 5f 06 22 83 c0 04 49 75 f4 8d 45 94 c7 00 75 39 4d 45 c7 40 04 7f b1 d6 33 c7 40 08 40 2e 06 e2 c7 40 0c a2 87 fb dd b9 04 00 00 00 81 30 ed 5f 06 22 83 c0 04 49 75 f4 8d 45 84 c7 00 99 f9 aa 66 c7 40 04 11 b7 d6 33 c7 40 08 4d 23 06 e2 c7 40 0c a2 e9 8e 02 b9 04 00 00 00 81 30 ed 5f 06 22 83 c0 04 49 75 f4 8d 85 b8 fe ff ff c7 00 b2 5f 59 22 c7 40 04 bd 5f 74 22 c7 40 08 82 5f 70 22 c7 40 0c 84 5f 62 22 c7 40 10 88 5f 74 22 c7 40 14 ac 5f 74 22 c7 40 18 8e 5f 6e 22 c7 40 1c 84 5f 72 22 c7 40 20 88 5f 65 22 c7 40 24 99 5f 73 22 c7 40 28 9f 5f 63 22 c7 40 2c ed 5f 06 22 b9 0c 00 00 00 81 30 ed 5f 06 22 83 c0 04 49 75 f4 8d 85 6c ff ff ff c7 00 bf 5f 49 22 c7 40 04 a2 5f 52 22 c7 40 08 b1 5f 45 22 c7 40 0c a4 5f 4b 22 c7 40 10 bb 5f 34 22 c7 40 14 ed 5f 06 22 b9 06 00 00 }
        $s4 = { 8d bd fc fe ff ff 32 c0 aa b9 2a 00 00 00 b0 ff f3 aa b0 3e aa b9 03 00 00 00 b0 ff f3 aa b0 3f aa b9 0a 00 00 00 b0 34 aa fe c0 e2 fb b9 03 00 00 00 b0 ff f3 aa 32 c0 aa b9 03 00 00 00 b0 ff f3 aa }
        $s5 = { 35 35 35 4f 35 58 35 22 36 35 36 3f 36 2c 37 3f 37 60 37 76 37 }
        $s6 = { 3d 2b 3d 47 3d 4d 3d 60 3d 67 3d 6d 3d }
        $s7 = { 8b 0e 0f b6 d1 0f b6 dd 57 8d bd fc fe ff ff 8a 04 3a 8a 24 3b c1 e9 10 83 c6 04 0f b6 d1 0f b6 cd 8a 1c 3a 8a 3c 39 5f 8a d4 8a f3 c0 e0 02 c0 eb 02 c0 e6 06 c0 e4 04 c0 ea 04 0a fe 0a c2 0a e3 88 07 88 7f 02 88 67 01 ff 4d fc }
    condition:
       uint16(0) == 0x5A4D and filesize > 25KB and 5 of ($s*) 
}  
