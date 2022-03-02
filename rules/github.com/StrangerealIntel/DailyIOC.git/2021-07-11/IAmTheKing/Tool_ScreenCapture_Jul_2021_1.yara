rule Tool_ScreenCapture_Jul_2021_1 {
   meta:
        description = "Detect Screen Capture utility"
        author = "Arkbird_SOLG"
        reference = "https://securelist.com/iamtheking-and-the-slothfulmedia-malware-family/99000/"
        date = "2021-07-09"
        // Build 2017
        hash1 = "f441e6239b592ac15538a8ba8903e5874283b066050a5a7e514ce33e84237f4e"
        tlp = "White"
        adversary = "IAmTheKing"
   strings:
        $s1 = "@MyScreen.jpg" fullword wide
        $s2 = "DISPLAY" fullword wide
        $s3 = "_invoke_watson" fullword ascii
        $s4 = "GdipSaveImageToStream" fullword ascii
        $s5 = { 8b 57 04 89 4d e8 8d 4d e8 51 52 e8 16 0c 00 00 85 c0 74 03 89 47 08 8b 75 e8 81 fe 00 04 00 00 77 18 56 e8 ac f9 ff ff 83 c4 04 84 c0 74 0b 8b c6 e8 9e 15 00 00 8b f4 eb 35 83 c8 ff 2b c6 83 f8 08 72 15 8d 46 08 50 ff 15 f4 30 40 00 83 c4 04 85 }
   condition:
     uint16(0) == 0x5a4d and ( filesize > 8KB and filesize < 60KB ) and 4 of ($s*)
}
