rule MAL_Kwampirs_Apr18 {
    meta:
        author = "Symantec"
        family = "Kwampirs"
        description = "Kwampirs dropper and main payload components"
        reference = "https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia"
        date = "2018-04-23"
    strings:
        $pubkey = {
            06 02 00 00 00 A4 00 00 52 53 41 31 00 08 00 00
            01 00 01 00 CD 74 15 BC 47 7E 0A 5E E4 35 22 A5
            97 0C 65 BE E0 33 22 F2 94 9D F5 40 97 3C 53 F9
            E4 7E DD 67 CF 5F 0A 5E F4 AD C9 CF 27 D3 E6 31
            48 B8 00 32 1D BE 87 10 89 DA 8B 2F 21 B4 5D 0A
            CD 43 D7 B4 75 C9 19 FE CC 88 4A 7B E9 1D 8C 11
            56 A6 A7 21 D8 C6 82 94 C1 66 11 08 E6 99 2C 33
            02 E2 3A 50 EA 58 D2 A7 36 EE 5A D6 8F 5D 5D D2
            9E 04 24 4A CE 4C B6 91 C0 7A C9 5C E7 5F 51 28
            4C 72 E1 60 AB 76 73 30 66 18 BE EC F3 99 5E 4B
            4F 59 F5 56 AD 65 75 2B 8F 14 0C 0D 27 97 12 71
            6B 49 08 84 61 1D 03 BA A5 42 92 F9 13 33 57 D9
            59 B3 E4 05 F9 12 23 08 B3 50 9A DA 6E 79 02 36
            EE CE 6D F3 7F 8B C9 BE 6A 7E BE 8F 85 B8 AA 82
            C6 1E 14 C6 1A 28 29 59 C2 22 71 44 52 05 E5 E6
            FE 58 80 6E D4 95 2D 57 CB 99 34 61 E9 E9 B3 3D
            90 DC 6C 26 5D 70 B4 78 F9 5E C9 7D 59 10 61 DF
            F7 E4 0C B3
        }

        $network_xor_key = {
            B7 E9 F9 2D F8 3E 18 57 B9 18 2B 1F 5F D9 A5 38
            C8 E7 67 E9 C6 62 9C 50 4E 8D 00 A6 59 F8 72 E0
            91 42 FF 18 A6 D1 81 F2 2B C8 29 EB B9 87 6F 58
            C2 C9 8E 75 3F 71 ED 07 D0 AC CE 28 A1 E7 B5 68
            CD CF F1 D8 2B 26 5C 31 1E BC 52 7C 23 6C 3E 6B
            8A 24 61 0A 17 6C E2 BB 1D 11 3B 79 E0 29 75 02
            D9 25 31 5F 95 E7 28 28 26 2B 31 EC 4D B3 49 D9
            62 F0 3E D4 89 E4 CC F8 02 41 CC 25 15 6E 63 1B
            10 3B 60 32 1C 0D 5B FA 52 DA 39 DF D1 42 1E 3E
            BD BC 17 A5 96 D9 43 73 3C 09 7F D2 C6 D4 29 83
            3E 44 44 6C 97 85 9E 7B F0 EE 32 C3 11 41 A3 6B
            A9 27 F4 A3 FB 2B 27 2B B6 A6 AF 6B 39 63 2D 91
            75 AE 83 2E 1E F8 5F B5 65 ED B3 40 EA 2A 36 2C
            A6 CF 8E 4A 4A 3E 10 6C 9D 28 49 66 35 83 30 E7
            45 0E 05 ED 69 8D CF C5 40 50 B1 AA 13 74 33 0F
            DF 41 82 3B 1A 79 DC 3B 9D C3 BD EA B1 3E 04 33
        }

        $decrypt_string = {
            85 DB 75 09 85 F6 74 05 89 1E B0 01 C3 85 FF 74
            4F F6 C3 01 75 4A 85 F6 74 46 8B C3 D1 E8 33 C9
            40 BA 02 00 00 00 F7 E2 0F 90 C1 F7 D9 0B C8 51
            E8 12 28 00 00 89 06 8B C8 83 C4 04 33 C0 85 DB
            74 16 8B D0 83 E2 0F 8A 92 1C 33 02 10 32 14 38
            40 88 11 41 3B C3 72 EA 66 C7 01 00 00 B0 01 C3
            32 C0 C3
        }

        $init_strings = {
            55 8B EC 83 EC 10 33 C9 B8 0D 00 00 00 BA 02 00
            00 00 F7 E2 0F 90 C1 53 56 57 F7 D9 0B C8 51 E8
            B3 27 00 00 BF 05 00 00 00 8D 77 FE BB 4A 35 02
            10 2B DE 89 5D F4 BA 48 35 02 10 4A BB 4C 35 02
            10 83 C4 04 2B DF A3 C8 FC 03 10 C7 45 FC 00 00
            00 00 8D 4F FC 89 55 F8 89 5D F0 EB 06
        }
    condition:
        2 of them
}
