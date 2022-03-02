rule RANSOM_Exorcist
{
    meta:
       
        description = "Rule to detect Exorcist"
        author = "McAfee ATR Team"
        date = "2020-09-01"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransomware:W32/Exorcist"
        actor_type = "Cybercrime"
        hash1 = "793dcc731fa2c6f7406fd52c7ac43926ac23e39badce09677128cce0192e19b0"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
    
    strings:

        $sq1 = { 48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 4C 89 60 20 55 41 56 41 57 48 8D 68 A1 48 81 EC 90 00 00 00 49 8B F1 49 8B F8 4C 8B FA 48 8B D9 E8 ?? ?? ?? ?? 45 33 E4 85 C0 0F 85 B1 00 00 00 48 8B D7 48 8B CB E8 9E 02 00 00 85 C0 0F 85 9E 00 00 00 33 D2 48 8B CB E8 ?? ?? ?? ?? 45 33 C0 48 8D 15 ?? ?? ?? ?? 48 8B CB E8 ?? ?? ?? ?? 45 8D 44 24 01 48 8B D7 48 8B C8 E8 ?? ?? ?? ?? 48 8B D0 48 8B CB 48 8B F8 FF 15 ?? ?? ?? ?? 4C 89 64 24 30 45 33 C9 C7 44 24 28 80 00 00 E8 45 33 C0 BA 00 00 00 C0 C7 44 24 20 03 00 00 00 48 8B CF FF 15 ?? ?? ?? ?? 4C 8B F0 48 8D 48 FF 48 83 F9 FD 77 25 48 8D 55 2F 48 8B C8 FF 15 ?? ?? ?? ?? 4C 39 65 2F 75 3B 49 8B CE FF 15 ?? ?? ?? ?? 48 8B CF FF 15 ?? ?? ?? ?? 48 8B CF E8 ?? ?? ?? ?? 4C 8D 9C 24 90 00 00 00 49 8B 5B 20 49 8B 73 28 49 8B 7B 30 4D 8B 63 38 49 8B E3 41 5F 41 5E 5D C3 48 8D 45 FB 4C 89 65 1F 4C 8D 4D FF 48 89 44 24 20 4C 8B C6 4C 89 65 07 48 8D 55 07 4C 89 65 FF 48 8D 4D 1F 44 89 65 FB E8 ?? ?? ?? ?? 45 33 C9 4C 8D 05 3C F5 FF FF 49 8B D7 49 8B CE FF 15 ?? ?? ?? ?? 48 8D 55 17 49 8B CE FF 15 ?? ?? ?? ?? 49 8B CE 44 89 65 F7 E8 ?? ?? ?? ?? 49 8B F4 4C 89 65 0F 4C 39 65 17 0F 8E 9D 00 00 00 C1 E0 10 44 8B F8 F0 FF 45 F7 B9 50 00 00 00 E8 ?? ?? ?? ?? 8B 4D 13 48 8B D8 89 48 14 89 70 10 4C 89 60 18 44 89 60 28 4C 89 70 30 48 8B 4D 07 48 89 48 48 48 8D 45 F7 B9 00 00 01 00 48 89 43 40 E8 ?? ?? ?? ?? 33 D2 48 89 43 20 41 B8 00 00 01 00 48 8B C8 E8 ?? ?? ?? ?? 48 8B 53 20 4C 8D 4B 38 41 B8 00 00 01 00 48 89 5C 24 20 49 8B CE FF 15 ?? ?? ?? ?? EB 08 33 C9 FF 15 ?? ?? ?? ?? 8B 45 F7 3D E8 03 00 00 77 EE 49 03 F7 48 89 75 0F 48 3B 75 17 0F 8C 6B FF FF FF EB 03 8B 45 F7 85 C0 74 0E 33 C9 FF 15 ?? ?? ?? ?? 44 39 65 F7 77 F2 48 8B 4D 07 E8 ?? ?? ?? ?? 48 8B 4D 1F 33 D2 E8 ?? ?? ?? ?? 49 8B CE FF 15 ?? ?? ?? ?? 4C 89 64 24 30 45 33 C9 C7 44 24 28 80 00 00 00 45 33 C0 BA 00 00 00 C0 C7 44 24 20 03 00 00 00 48 8B CF FF 15 ?? ?? ?? ?? 48 8B D8 48 8D 48 FF 48 83 F9 FD 77 51 48 8D 55 37 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B 55 37 45 33 C9 45 33 C0 48 8B CB FF 15 ?? ?? ?? ?? 44 8B 45 FB 4C 8D 4D 27 48 8B 55 FF 48 8B CB 4C 89 64 24 20 FF 15 ?? ?? ?? ?? 48 8B 4D FF E8 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? E9 14 FE FF FF 48 8B CF E8 ?? ?? ?? ?? 48 8B 4D FF E9 06 FE FF FF }          
        $sq2 = { 48 8B C4 48 81 EC 38 01 00 00 48 8D 50 08 C7 40 08 04 01 00 00 48 8D 4C 24 20 FF 15 ?? ?? ?? ?? 48 8D 4C 24 20 E8 ?? ?? ?? ?? 48 81 C4 38 01 00 00 C3 } 

    condition:

        uint16(0) == 0x5a4d and
         any of them 
}

