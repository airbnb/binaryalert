rule Mal_PlugX_Thor_July_2021_1
{
    meta:
        description = "Detect Thor variant of PlugX (Variant 1)"
        author = "Arkbird_SOLG"
        date = "2021-07-27"
        reference = "https://unit42.paloaltonetworks.com/thor-plugx-variant/"
        hash1 = "125fdf108dc1ad6f572cbdde74b0c7fa938a9adce0cc80cb5ce00f1c030b0c93"
        hash2 = "690c488a9902978f2ef05aa23d21f4fa30a52dd9d11191f9b49667cd08618d87"
        hash3 = "3c5e2a4afe58634f45c48f4e800dc56bae3907dde308ff97740e9cd5684d1c53"
        hash4 = "a9cbce007a7467ba1394eed32b9c1774ad09a9a9fb74eb2ccc584749273fac01"
        tlp = "white"
        adversary = "Chinese APT group"
    strings:
        $s1 = { 55 8b ec 81 ec ?? 01 00 00 a1 00 [2] 10 33 c5 89 45 [2-10] 85 ?? fe ff ff [0-1] c6 85 ?? fe ff ff 5c c6 85 ?? fe ff ff ?? c6 85 ?? fe ff ff ?? c6 85 ?? fe ff ff ?? c6 85 ?? fe ff ff }
        $s2 = { 8b ?? ?? fe ff ff c6 ?? 00 [3-5] fe ff ff [4-10] fe ff ff }
        $s3 = { fe ff ff 6a 40 68 00 10 00 00 8b 95 ?? fe ff ff 52 6a 00 ff 95 ?? fe ff ff 89 85 ?? fe ff ff }
    condition:
       uint16(0) == 0x5A4D  and filesize > 25KB and all of ($s*) 
}  
