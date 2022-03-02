rule RAN_Lockfile_Aug_2021_1 {
   meta:
        description = "Detect Lockfile ransomware (unpacked version)"
        author = "Arkbird_SOLG"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/lockfile-ransomware-new-petitpotam-windows"
        date = "2021-08-28"
        hash1 = "3303a19789a73fa70a107f8e35a4ce10bb4f6a69ac041a1947481ed8ae99a11c"
        level = "experimental"
        adversary = "Lockfile"
   strings:
        $s1 = { 80 32 41 48 8d 52 01 ff c1 81 f9 d1 57 00 00 72 ef 4c 8d 05 78 d4 06 00 33 d2 33 c9 ff 15 06 9a 05 00 48 8b d8 ff 15 0d 9a 05 00 48 8b cb 3d b7 00 00 00 75 14 ff 15 0d 9a 05 00 33 c0 48 81 c4 d0 03 00 00 41 5c 5b 5d c3 4c 89 b4 24 c8 03 00 00 4c 89 bc 24 c0 03 00 00 ff 15 e9 99 05 00 ff }
        $s2 = "winsta0\\default" fullword ascii
        $s3 = { 55 56 57 48 8d 6c 24 f0 48 81 ec 10 01 00 00 33 db 48 8b f1 48 89 5c 24 68 48 89 5d 40 48 89 5c 24 60 ff 15 0b a2 05 00 8b c8 89 45 38 48 8d 54 24 68 ff 15 1b a5 05 00 0f 57 c0 8d 7b 30 33 c0 48 89 45 00 48 89 45 98 48 8d 05 d4 db 06 00 0f 11 45 a0 c7 45 a0 68 00 00 00 0f 11 45 b0 48 89 45 b0 0f 11 45 c0 0f 11 45 d0 0f 11 45 e0 0f 11 45 f0 0f 11 45 88 ff 15 17 a2 05 00 4c 8d 44 24 60 ba eb 01 02 00 48 8b c8 ff 15 4c a1 05 00 85 c0 0f 84 10 01 00 00 4c 8d 44 24 70 33 c9 48 8d 15 8e db 06 00 ff 15 28 a1 05 00 85 c0 0f 84 f4 00 00 00 48 8b 44 24 70 44 8d 4b 01 48 8b 4c 24 60 45 33 c0 48 89 44 24 7c ba 00 00 00 02 48 8d 45 40 c7 44 24 78 01 00 00 00 48 89 44 24 28 c7 44 24 20 01 00 00 00 c7 45 84 02 00 00 00 ff 15 ef a0 05 00 85 }
        $s4 = { 48 8d 85 18 03 00 00 40 88 74 24 53 48 89 44 24 30 4c 8d 4c 24 44 48 8b 05 57 04 0c 00 48 8d 15 f0 dd 06 00 48 89 44 24 28 48 8d 8d d0 01 00 00 48 8d 45 b0 4c 8b c3 48 89 44 24 20 e8 13 f3 ff ff 48 89 74 24 30 48 8d 8d d0 01 00 00 c7 44 24 28 80 00 00 00 45 33 c9 45 33 c0 c7 44 24 20 02 00 00 00 ba 00 00 00 c0 ff 15 a6 a3 05 00 44 8b 05 8f fe 07 00 48 8d 4d 88 48 8b f8 e8 23 b5 ff ff 48 83 }
        $s5 = { 3c 63 6f 6d 70 75 74 65 72 6e 61 6d 65 3e 25 73 3c 2f 63 6f 6d 70 75 74 65 72 6e 61 6d 65 3e 00 3c 62 6c 6f 63 6b 6e 75 6d 3e 25 64 3c 2f 62 6c 6f 63 6b 6e 75 6d 3e 00 25 73 5c 25 73 2d 25 73 2d 25 64 25 73 }
        $s6 = { 33 d2 48 8d 8d c0 00 00 00 41 b8 04 01 00 00 e8 48 99 03 00 48 8d 95 10 03 00 00 c7 85 10 03 00 00 04 01 00 00 48 8d 4d b0 ff 15 c5 a5 05 00 4c 8d 45 b0 48 8d 15 2a df 06 00 48 8d 8d c0 00 00 00 e8 96 f4 ff ff 44 8d 46 02 48 8d 15 33 df 06 00 48 8d 4c 24 68 e8 81 f4 ff ff c6 85 18 03 00 00 2f 8b ce c6 85 19 03 00 00 69 c6 85 1a 03 00 00 75 c6 85 1b 03 00 00 62 40 88 b5 1c 03 00 00 0f b6 }
   condition:
        uint16(0) == 0x5a4d and filesize > 10KB and 5 of ($s*)
}
