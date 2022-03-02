rule MAL_CobaltStrike_Oct_2021_1 {
    meta:
        description = "Detect Cobalt Strike implant"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/malwrhunterteam/status/1454154412902002692"
        date = "2021-10-30"
        hash1 = "f520f97e3aa065efc4b7633735530a7ea341f3b332122921cb9257bf55147fb7"
        hash2 = "7370c09d07b4695aa11e299a9c17007e9267e1578ce2753259c02a8cf27b18b6"
        hash3 = "bfbc1c27a73c33e375eeea164dc876c23bca1fbc0051bb48d3ed3e50df6fa0e8"
        tlp = "white"
        adversary = "-"
    strings:
        $s1 = { 48 83 ec 10 4c 89 14 24 4c 89 5c 24 08 4d 33 db 4c 8d 54 24 18 4c 2b d0 4d 0f 42 d3 65 4c 8b 1c 25 10 00 00 00 4d 3b d3 f2 73 17 66 41 81 e2 00 f0 4d 8d 9b 00 f0 ff ff 41 c6 03 00 4d 3b d3 f2 75 ef 4c 8b 14 24 4c 8b 5c 24 08 48 83 c4 10 f2 c3 }
        $s2 = { 89 ?? 24 ?? 8b ?? 24 0c 89 ?? 24 ?? 8b ?? 24 ?? c1 ?? 0d 89 ?? 24 0c 48 8b ?? 24 10 89 ?? 24 [2] 8b ?? 24 10 }
        $s3 = { b8 10 00 00 00 48 89 45 ?? e8 [3] 00 48 29 c4 48 89 e0 48 8b 4d ?? 48 89 45 ?? 48 89 c8 e8 [3] 00 48 29 c4 48 89 e0 48 8b 4d ?? 48 89 45 ?? 48 89 c8 e8 [3] 00 48 29 c4 48 89 e0 48 8b 4d ?? 48 89 45 ?? 48 89 c8 e8 [3] 00 48 29 c4 48 89 e0 48 8b 4d ?? 48 89 45 ?? 48 89 c8 e8 [3] 00 48 29 c4 48 89 e0 48 8b 4d ?? 8b 55 f8 89 11 4c 8b 45 ?? 4c 8b 4d f0 4d 89 08 4c 8b 55 ?? 4c 8b 5d e8 4d 89 1a 48 8b 75 ?? 48 8b 7d e0 48 89 3e c7 00 ?? 00 00 00 48 8b 05 [3] 00 48 05 [2] 00 00 8b 19 4d 8b 00 4d 8b 32 48 8b 0e 48 83 ec 20 4c 89 f2 41 89 d9 ff d0 48 83 c4 20 ?? 45 }
        $s4 = { 48 83 ec 48 44 89 4c 24 44 4c 89 44 24 38 48 89 54 24 30 48 89 4c 24 28 c7 44 24 24 ?? 00 00 00 48 8b 05 [3] 00 48 05 [2] 00 00 44 8b 4c 24 44 4c 8b 44 24 38 48 8b 54 24 30 48 8b 4c 24 28 ff d0 90 48 83 c4 }
    condition:
        uint16(0) == 0x5A4D and filesize > 20KB and 3 of ($s*) 
}
