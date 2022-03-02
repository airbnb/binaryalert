import "pe"

rule Win32_Virus_DeadCode : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "DEADCODE"
        description         = "Yara rule that detects DeadCode virus."

        tc_detection_type   = "Virus"
        tc_detection_name   = "DeadCode"
        tc_detection_factor = 5

    strings:
        $deadcode_ep_1 = {
            64 67 FF 36 30 00 58 8B 40 08 FF 70 48 5B FF 70 4C 5A 03 40 44 
            FF E0 
        }
        
        $deadcode_marker = {
            DE C0 AD DE
        }
  
        $deadcode_ep_2 = {
            2B C0 85 C0 74 0E 64 67 FF 36 00 00 64 67 89 26 00 00 89 00 E8 
            ED FF FF FF 8B 74 24 0C 64 67 A1 30 00 8B 40 08 8B 58 48 8B 50 
            4C 03 40 44 89 86 B8 00 00 00 89 86 B0 00 00 00 89 9E A4 00 00 
            00 89 96 A8 00 00 00 2B C0 C3
        }
  
        $deadcode_ep_3 = {
            B8 DE C0 AD DE 50 5A 64 67 A1 30 00 8B 40 08 8B 58 48 8B 50 4C
            03 40 44 FF D0
        }

        $deadcode_body_1 = {
            8B D0 8B EA 81 C5 ?? ?? ?? ?? 89 85 A4 00 00 00 89 9D C0 00 00 00 E8 56 01 00 00 89
            45 00 8D 75 04 81 C2 ?? ?? ?? ?? 6A 19 FF 75 00 52 56 E8 CE 01 00 00 64 67 A1 30 00 
            8B 40 08 89 85 88 00 00 00 C7 85 D0 00 00 00 ?? ?? ?? ?? E8 09 00 00 00 8B 64 24 08 
            E9 03 01 00 00 33 D2 64 FF 32 64 89 22 83 BD C0 00 00 00 00 75 2F 6A 04 68 00 10 00 
            00 68 40 01 00 00 6A 00 FF 55 08 50 8F 45 78 E8 2A 03 00 00 68 00 40 00 00 68 40 01 
            00 00 FF 75 78 FF 55 28 E9 C3 00 00 00 8B 85 A4 00 00 00 05 ?? ?? ?? ?? 8D B5 B4 00 
            00 00 56 6A 00 55 50 68 00 00 10 00 6A 00 FF 55 30 89 85 AC 00 00 00 6A 04 68 00 10 
            00 00 6A 54 6A 00 FF 55 08 89 85 A8 00 00 00 64 67 A1 30 00 8B 40 10 8B 40 3C 8B B5
            A8 00 00 00 8D 7E 10 56 57 6A 00 6A 00 6A 04 6A 01 6A 00 6A 00 50 6A 00 FF 55 50 85 
            C0 74 5D FF 76 04 8F 85 B0 00 00 00 64 67 A1 30 00 8B 40 08 8B D8 03 5B 3C 8B 5B 28 
            03 D8 8B 8D A4 00 00 00 81 ?? ?? ?? ?? 8D 85 B4 00 00 00 50 6A ?? 51 53 FF 36 FF 55 
            4C FF 76 04 FF 55 54 8D B5 AC 00 00 00 6A FF 6A 01 56 6A 02 FF 55 34 68 00 40 00 00 
            6A 54 FF B5 A8 00 00 00 FF 55 28 33 D2 64 8F 02 5A E8 DB 01 00 00 E8 F5 00 00 00 6A 
            00 FF 55 3C 64 67 8B 36 00 00 AD 83 F8 FF 74 04 8B F0 EB F6 8B 7E 04 81 E7 00 00 FF 
            FF 66 81 3F 4D 5A 74 08 81 EF 00 00 01 00 EB F1 8B DF 03 5B 3C 66 81 3B 50 45 74 02 
            EB E3 8B C7 C3 55 8B EC 8B 75 0C AC 84 C0 75 FB 2B 75 0C 8B CE 8B 5D 08 03 5B 3C 8B 
            5B 78 03 5D 08 8B 53 20 03 55 08 2B C0 8B 32 03 75 08 8B 7D 0C 51 FC F3 A6 59 74 06
        }

        $deadcode_body_2 = { 
            83 C2 04 40 EB EB 8B 73 24 03 75 08 2B D2 66 8B 14 46 8B 73 1C 03 75 08 8B 04 96 03 
            45 08 8B E5 5D C2 08 00 55 8B EC 8B 7D 08 8B 75 0C 8B 4D 14 51 56 57 56 FF 75 10 E8
            91 FF FF FF 5F 5E 59 AB AC 84 C0 75 FB E2 E9 8B E5 5D C2 10 00 8B 6C 24 04 6A 04 68 
            00 10 00 00 68 40 01 00 00 6A 00 FF 55 08 85 C0 74 18 89 45 78 E8 63 01 00 00 68 00 
            40 00 00 68 40 01 00 00 FF 75 78 FF 55 28 6A 00 FF 55 40 C3 
        }   
  
    condition:
        uint16(0) == 0x5A4D and 
        ((($deadcode_ep_1 at pe.entry_point) and ($deadcode_marker at 0x40)) or
        (($deadcode_ep_2 at pe.entry_point) and ($deadcode_marker at 0x40)) or
        (($deadcode_ep_3 at pe.entry_point) and ($deadcode_marker at 0x40)) or
        ($deadcode_body_1 and $deadcode_body_2))
}