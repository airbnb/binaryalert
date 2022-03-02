import "pe"

rule Win32_Virus_Elerad : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "ELERAD"
        description         = "Yara rule that detects Elerad virus."

        tc_detection_type   = "Virus"
        tc_detection_name   = "Elerad"
        tc_detection_factor = 5

    strings:
        $elerad_body = {
            EB 77 60 E8 09 00 00 00 8B 64 24 08 E9 DD 01 00 00 33 D2 64 FF 32 64 89 22 50 8B D8 B9 FF 00 00 00 81 38 2E 65 78 65 74
            08 40 E2 F5 E9 BD 01 00 00 32 D2 38 50 04 0F 85 B2 01 00 00 33 D2 80 38 5C 74 07 3B C3 74 07 48 E2 F4 88 10 8B D0 58 BE
            00 00 E6 77 BF 23 C1 AB 00 EB 3E 60 E8 09 00 00 00 8B 64 24 08 E9 84 01 00 00 33 D2 64 FF 32 64 89 22 BE 00 00 E6 77 EB
            20 68 ?? ?? ?? ?? 60 8B 74 24 24 E8 09 00 00 00 8B 64 24 08 E9 5D 01 00 00 33 D2 64 FF 32 64 89 22 E8 00 00 00 00 5D 81
            ED ?? ?? ?? ?? 81 FF 23 C1 AB 00 75 0C 89 95 22 12 40 00 89 85 1E 12 40 00 BA ?? ?? ?? ?? B9 09 02 00 00 8D 85 D0 10 40
            00 31 10 83 C0 04 E2 F9
        }

    condition:
        uint16(0) == 0x5A4D and 
        ($elerad_body at pe.entry_point)
}