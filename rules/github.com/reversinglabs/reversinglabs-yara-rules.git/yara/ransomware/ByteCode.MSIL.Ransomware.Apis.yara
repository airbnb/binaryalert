rule ByteCode_MSIL_Ransomware_Apis : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "APIS"
        description         = "Yara rule that detects Apis ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Apis"
        tc_detection_factor = 5

    strings:

        $find_files = {
            28 ?? ?? ?? ?? 13 ?? 16 13 ?? 2B ?? 11 ?? 11 ?? 9A 0A 06 6F ?? ?? ?? ?? 72 ?? ?? ?? ??
            28 ?? ?? ?? ?? 2C ?? 06 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 11 ?? 17 58 13 ?? 11 ?? 11 ?? 8E
            69 32 ?? 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0B 7E ?? ?? ?? ??
            7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0C 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 72 ?? ??
            ?? ?? 28 ?? ?? ?? ?? 0D 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13
            ?? 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 7E ?? ?? ?? ?? 7E
            ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 72 ?? ??
            ?? ?? 28 ?? ?? ?? ?? 13 ?? 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ??
            13 ?? 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 7E ?? ?? ?? ??
            7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 72 ??
            ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ??
            ?? 13 ?? 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 07 28 ?? ??
            ?? ?? 08 28 ?? ?? ?? ?? 09 28 ?? ?? ?? ?? 11 ?? 28 ?? ?? ?? ?? 11 ?? 28 ?? ?? ?? ?? 11
            ?? 28 ?? ?? ?? ?? 11 ?? 28 ?? ?? ?? ?? 11 ?? 28 ?? ?? ?? ?? 11 ?? 28 ?? ?? ?? ?? 11 ??
            28 ?? ?? ?? ?? 11 ?? 28 ?? ?? ?? ?? 11 ?? 28 ?? ?? ?? ?? 11 ?? 28 ?? ?? ?? ?? 2A
        }

        $encrypt_files = {
            02 28 ?? ?? ?? ?? 0A 17 0B 16 0C 38 ?? ?? ?? ?? 73 ?? ?? ?? ?? 13 ?? 11 ?? 06 08 9A 28
            ?? ?? ?? ?? 7D ?? ?? ?? ?? 06 08 9A 28 ?? ?? ?? ?? 0D 7E ?? ?? ?? ?? 11 ?? FE 06 ?? ??
            ?? ?? 73 ?? ?? ?? ?? 28 ?? ?? ?? ?? 39 ?? ?? ?? ?? 09 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 39
            ?? ?? ?? ?? 06 08 9A 73 ?? ?? ?? ?? 13 ?? 11 ?? 20 ?? ?? ?? ?? 6F ?? ?? ?? ?? 11 ?? 6F
            ?? ?? ?? ?? 20 ?? ?? ?? ?? 6A 2F ?? 28 ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ??
            18 5B 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 13 ?? 06 08 9A 11 ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ??
            06 08 9A 06 08 9A 72 ?? ?? ?? ?? 1A 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2B ??
            28 ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 1A 5B 28 ?? ?? ?? ?? 6F ?? ?? ?? ??
            13 ?? 06 08 9A 11 ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 06 08 9A 06 08 9A 72 ?? ?? ?? ?? 1A
            28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 07 2C ?? 16 0B 02 72 ?? ?? ?? ?? 7E ?? ??
            ?? ?? 28 ?? ?? ?? ?? 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? DE ?? 26 DE ?? 08 17 58 0C 08 06 8E
            69 3F ?? ?? ?? ?? 02 28 ?? ?? ?? ?? 13 ?? 16 13 ?? 2B ?? 11 ?? 11 ?? 9A 28 ?? ?? ?? ??
            11 ?? 17 58 13 ?? 11 ?? 11 ?? 8E 69 32 ?? DE ?? 26 DE ?? 2A
        }

        $setup_env = {
            28 ?? ?? ?? ?? 2C ?? 17 28 ?? ?? ?? ?? 7E ?? ?? ?? ?? 2C ?? 28 ?? ?? ?? ?? 7E ?? ?? ??
            ?? 2C ?? 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 7E ?? ?? ?? ?? 2C ?? 28 ?? ?? ?? ?? 7E ?? ?? ??
            ?? 2C ?? 28 ?? ?? ?? ?? 7E ?? ?? ?? ?? 2C ?? 28 ?? ?? ?? ?? 2B ?? 7E ?? ?? ?? ?? 2C ??
            7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 7E ?? ?? ?? ?? 2C ?? 28 ?? ?? ?? ?? 7E ?? ?? ?? ?? 2C ??
            28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 7E ?? ?? ?? ?? 2D ?? 14 FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ??
            80 ?? ?? ?? ?? 7E ?? ?? ?? ?? 73 ?? ?? ?? ?? 28 ?? ?? ?? ?? 7E ?? ?? ?? ?? 2C ?? 7E ??
            ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2A
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $setup_env
        ) and
        (
            $find_files
        ) and
        (
            $encrypt_files
        )
}