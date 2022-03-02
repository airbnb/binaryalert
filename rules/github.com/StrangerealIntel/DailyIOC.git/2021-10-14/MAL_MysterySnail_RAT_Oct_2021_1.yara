rule MAL_MysterySnail_RAT_Oct_2021_1 {
   meta:
        description = "Detect MysterySnaial RAT implant"
        author = "Arkbird_SOLG"
        reference = "https://securelist.com/mysterysnail-attacks-with-windows-zero-day/104509/"
        date = "2021-10-13"
        hash1 = "e84be291efadd53a8bb965bfb589590ffe870da9187e6752cc7a9f028053ff5d"
        hash2 = "b7fb3623e31fb36fc3d3a4d99829e42910cad4da4fa7429a2d99a838e004366e"
        hash3 = "73f520223a2e01c036a4b620c7188e733c113a429e25c5c3de7fbbc1c3d16ccc"
        level = "experimental"
        tlp = "White"
        adversary = "MysterySnail"
    strings:
        // File script
        $s1 = { 57 48 83 ec 20 4c 8b c2 33 f6 0f b6 d1 41 b1 01 8b c2 c1 e8 04 41 84 c1 75 53 4d 85 c0 74 47 41 0f b7 08 8d 41 bf 66 83 f8 19 76 0a 66 83 e9 61 66 83 f9 19 77 08 66 41 83 78 02 3a 74 03 44 8a ce 45 84 c9 49 8d 40 04 49 8b c8 48 0f 45 c8 66 39 31 74 19 66 83 39 5c 74 06 66 83 39 2f 75 06 66 39 71 02 74 07 bb 00 80 00 00 eb 05 bb 40 40 00 00 66 c1 e2 07 b8 80 00 00 00 66 f7 d2 66 23 d0 b8 00 01 00 00 66 0b d0 66 0b da 4d 85 c0 74 65 ba 2e 00 00 00 49 8b c8 e8 64 4b 01 00 48 8b f8 48 85 c0 74 50 48 8d 15 a9 0d 09 00 48 8b c8 e8 5d dd 00 00 85 c0 74 39 48 8d 15 a6 0d 09 00 48 8b cf e8 4a dd 00 00 85 c0 74 26 48 8d 15 a3 0d 09 00 48 8b cf e8 37 dd 00 00 85 c0 74 13 48 8d 15 a0 0d 09 00 48 8b cf e8 24 dd 00 00 85 c0 75 04 66 83 cb 40 48 8b 74 24 38 0f b7 c3 66 c1 e8 03 66 83 e0 38 66 0b d8 0f b7 c3 66 c1 e8 06 66 83 e0 07 66 0b c3 48 8b 5c 24 30 }
        // OpenSSL ref
        $s2 = { 4c 8d 0d 6e 96 09 00 48 89 44 24 20 44 8b c7 48 8d 15 a7 62 0d 00 48 8b ce e8 47 17 fb ff 85 c0 0f 8e 83 00 00 00 4c 8d 0d 48 96 09 00 44 8b c7 48 8d 15 36 59 0d 00 48 8b ce e8 26 17 fb ff 85 c0 7e 66 49 8b 46 10 8b 08 81 f9 0a 04 00 00 74 1b 81 f9 3f 04 00 00 74 13 81 f9 0b 04 00 00 44 8b c3 41 0f }
        $s3 = { 25 2a 73 70 75 62 3a 0a }
        // check proxy enabled (proxyserver)
        $s4 = { 48 81 ec b0 02 00 00 48 8b 05 7a e9 7b 00 48 33 c4 48 89 84 24 a0 02 00 00 48 8b ea 48 8d 44 24 38 48 8d 15 c0 a1 79 00 48 89 44 24 20 41 b9 01 00 00 00 45 33 c0 48 c7 c1 01 00 00 80 ff 15 3d 94 71 00 85 c0 75 53 48 8b 4c 24 38 48 8d 44 24 30 48 89 44 24 28 4c 8d 4c 24 34 48 8d 84 24 d0 01 00 00 c7 44 24 34 01 00 00 00 45 33 c0 48 89 44 24 20 48 8d 15 e6 a1 79 00 c7 44 24 30 c7 00 00 00 ff 15 00 94 71 00 85 c0 75 0e 8b 84 24 d0 01 00 00 89 45 68 85 c0 75 07 33 c0 e9 eb 00 00 00 83 f8 01 75 f4 33 d2 48 8d 4c 24 40 41 b8 90 01 00 00 e8 f0 82 6f 00 48 8b 4c 24 38 48 8d 44 24 30 48 89 44 24 28 4c 8d 4c 24 34 48 8d 44 24 40 c7 44 24 30 c8 00 00 00 45 33 c0 48 89 44 24 20 48 8d 15 90 a1 79 00 ff 15 9a 93 71 00 85 c0 75 a8 33 f6 8b fe 8b de 66 83 7c 5c 40 3a 74 15 48 83 fb 64 74 94 ff c7 48 ff c3 48 83 fb 64 7c e7 33 c0 eb 77 48 63 c7 48 8d 4c 24 42 4c 89 b4 24 d0 02 00 00 4c 8d 34 00 49 03 ce e8 2f ad 6f 00 89 45 64 49 81 }
        // object abuse
        $s5 = { 48 8d 4c 24 60 ff 97 18 04 00 00 33 f6 c7 45 90 01 00 00 00 0f 57 c0 48 89 74 24 68 33 c9 66 0f 7f 44 24 70 48 89 75 80 48 89 75 88 c7 45 94 01 00 00 00 48 c7 45 9c 01 00 00 00 48 89 75 a8 e8 32 97 6f 00 8d 4e 01 48 89 45 b0 e8 26 97 6f 00 8d 4e 02 48 89 45 b8 e8 1a 97 6f 00 48 89 45 c0 45 33 c9 48 8d 45 d0 45 33 c0 48 89 44 24 48 48 8b d3 48 8d 44 24 60 33 c9 48 89 44 24 40 48 89 74 24 38 48 89 74 24 30 89 74 24 28 c7 44 24 20 01 00 00 00 ff 97 90 03 00 00 85 c0 74 0a 48 8b 4d d8 ff 15 da 8f 71 00 48 8b 4d d0 ff 15 d0 8f 71 00 b9 10 27 00 00 ff 15 b5 8f 71 00 0f 10 05 96 9c 79 00 48 8d 4d 08 33 d2 f2 0f 10 0d 98 9c 79 00 41 b8 b8 07 00 00 0f 29 45 f0 f2 0f 11 4d 00 e8 84 7d 6f 00 4c 8d 05 65 9c 79 00 48 8d 55 f0 48 8d 4c 24 58 e8 c3 98 6f 00 85 c0 0f 85 af 00 00 00 48 8b 4c 24 58 44 8d 40 02 33 d2 e8 db aa 6f 00 48 8b 4c 24 58 e8 71 94 6f 00 48 8b 4c 24 58 45 33 c0 33 d2 48 63 d8 e8 bf aa 6f 00 8d 4b 01 48 63 c9 e8 d4 67 6f 00 4c 8b 4c 24 58 4c 8b c3 ba 01 00 00 00 48 8b c8 48 8b f0 e8 58 f5 6f 00 48 8b 4c 24 58 48 8b d8 e8 47 99 6f 00 b9 64 00 00 00 ff 15 08 8f 71 00 48 83 bf f0 03 00 00 00 75 11 b9 42 6e aa cf e8 8c e7 ff ff 48 89 87 f0 03 00 00 48 8d 4d f0 ff 97 f0 03 00 00 44 8b cb 89 5c 24 50 4c 8b c6 48 8d 54 24 50 49 8b ce e8 44 d7 5c 00 48 8b ce 85 }
    condition:
        uint16(0) == 0x5A4D and filesize > 500KB and all of ($s*)
}
