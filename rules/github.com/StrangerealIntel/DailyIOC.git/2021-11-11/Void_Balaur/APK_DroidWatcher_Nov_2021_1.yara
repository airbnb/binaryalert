rule APK_DroidWatcher_Nov_2021_1 {
    meta:
        description = "Detect modified DroidWatcher stealer used by Void Balaur group"
        author = "Arkbird_SOLG"
        reference ="https://documents.trendmicro.com/assets/white_papers/wp-void-balaur-tracking-a-cybermercenarys-activities.pdf"
        date = "2021-11-11"
        hash1 = "902c5f46ac101b6f30032d4c5c86ecec115add3605fb0d66057130b6e11c57e6"
        tlp = "white"
        level = "Experimental"
        adversary = "Void Balaur"
    strings:
        $s1 = { 38 50 F4 59 CC FF F3 37 65 28 4F 35 1A D2 83 C9 6C E0 20 27 38 C5 39 2E 72 95 5B 3C E0 29 D1 9E C7 0C A4 21 1B 55 09 A5 0B 83 99 C8 7C D6 F2 0F 47 B9 CE 43 82 5E C4 0C }
        $s2 = { 3C E2 39 81 D4 EA 82 1F F8 83 42 54 A0 2E 6D E8 C5 44 E6 B0 92 13 5C E6 21 EF 89 9D 26 28 90 8C 3C 94 A3 36 AD E9 CD 48 26 B2 92 1D 1C E4 34 57 B9 C7 2B A2 7D 1E 14 A8 4A 4D 5A D3 8E 2E F4 A4 1F 83 19 C1 58 A6 32 9B 05 2C 63 03 DB B9 42 }
        $s3 = { F0 96 6F 33 59 1B BA 32 82 8D 5C 22 28 B3 1E 4C 65 BA 31 99 4D 1C E0 2E 89 7E F3 1E 94 A7 13 13 08 E7 22 31 7E D7 EB 28 42 53 46 B0 81 73 7C 22 E3 1F 62 4E 17 66 B2 8F 47 A4 CA A2 D6 68 C9 44 36 72 9D 78 7F 7A 16 B5 18 CA 5A 4E F2 92 74 59 } 
        $s4 = { 3D 57 89 56 4D 9E 51 9C CE 2C 20 92 B8 D5 C5 81 7A 8C 65 03 17 F9 C0 77 35 5C 4F 0B 26 B0 99 0B C4 A9 69 5D A9 44 0F 66 F2 2F F7 48 5C 4B 7E 50 9D 41 2C E0 34 AF 89 5F 5B 9E 50 92 C6 F4 65 3C 0B D8 CA 1E CE F3 80 CF EA B8 9E 94 A4 E5 37 72 51 88 0A 34 A3 2F 03 19 CE 41 22 B8 C9 5D 1E F2 82 77 44 AF AB }
        $s5 = { FA D6 A4 0F EB 79 42 D2 76 F6 54 BA B2 9A 27 FC D0 5E 9E 30 8D 2B 24 E9 A0 AE A8 41 33 06 32 84 51 8C 63 12 33 98 CF 72 36 B0 8B 83 1C E3 12 D7 B8 CD 63 5E 13 B3 A3 FE 45 06 8A D0 80 3E 0C 66 32 33 59 C6 66 0E 10 C1 39 AE F3 84 D7 C4 EF E4 EC C8 37 64 22 17 F9 28 42 45 3A 31 9E A5 EC E1 14 37 79 C0 DB FF FD B6 B3 E7 F3 3B 45 A9 45 28 E3 D9 }
    condition:
        uint32be(0) == 0x504B0304 and filesize > 300KB and 4 of them
}
