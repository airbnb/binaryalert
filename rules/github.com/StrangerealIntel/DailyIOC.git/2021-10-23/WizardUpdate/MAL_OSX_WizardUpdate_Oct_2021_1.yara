rule MAL_OSX_WizardUpdate_Oct_2021_1 {
   meta:
        description = "Detect WizardUpdate installer on OSX system"
        author = "Arkbird_SOLG"
        reference1 = "https://twitter.com/MsftSecIntel/status/1451279679059488773"
        date = "2021-10-22"
        hash1 = "939cebc99a50989ffbdbb2a6727b914fc9b2382589b4075a9fd3857e99a8c92a3"
        hash2 = "c5017798275f054ae96c69f5dd0b378924c6504a70c399279bbf7f33d990d45b"
        hash3 = "7067e6a69a8f5fdbabfb00d03320cfc2f3584a83304cbeeca7e8edc3d57bbbd4"
        tlp = "White"
        adversary = "-"
    strings:
        // Exec command reference
        $s1 = { 48 89 e5 48 83 ec 70 48 89 7d f0 48 c7 45 e0 00 00 00 00 b8 01 00 00 00 48 89 c7 48 89 c6 e8 b8 3b 00 00 31 c9 89 cf 48 89 45 d8 48 c7 45 d0 00 00 00 00 e8 a9 3b 00 00 48 8b 7d f0 48 8d 35 d4 3f 00 00 89 45 cc e8 ba 3b 00 00 48 89 45 e8 48 83 7d e8 00 0f 85 0d 00 00 00 48 c7 45 f8 00 00 00 00 e9 cd 00 00 00 e9 00 00 00 00 48 8b 55 e8 48 8d 7d e0 48 8d 75 d0 e8 70 3b 00 00 48 83 f8 ff 0f 84 9c 00 00 00 48 8b 7d d8 48 8b 45 d8 48 89 7d c0 48 89 c7 e8 76 3b 00 00 48 8b 7d e0 48 89 45 b8 e8 69 3b 00 00 48 8b 4d b8 48 01 c1 48 81 c1 01 00 00 00 48 8b 7d c0 48 89 ce e8 49 3b 00 00 48 89 45 d8 48 8b 45 d8 48 8b 7d d8 48 89 45 b0 e8 3a 3b 00 00 48 8b 4d b0 48 01 c1 48 8b 75 e0 48 8b 7d e0 48 89 4d a8 48 89 75 a0 e8 1e 3b 00 00 48 05 01 00 00 00 48 8b 7d a8 48 8b 75 a0 48 89 c2 e8 0e 3b 00 00 48 8b 7d e0 48 89 45 98 e8 d1 3a 00 00 48 c7 45 }
        $s2 = { 48 89 e5 48 81 ec 80 01 00 00 48 89 f8 48 8b 0d 7b 31 00 00 48 8b 09 48 89 4d f8 48 89 bd e8 fe ff ff c6 85 e7 fe ff ff 00 48 89 bd b8 fe ff ff 48 89 b5 b0 fe ff ff 48 89 85 a8 fe ff ff e8 9c 01 00 00 c7 85 d4 fe ff ff 00 01 00 00 48 8d 35 0a 2e 00 00 48 8b bd b0 fe ff ff e8 df 28 00 00 e9 00 00 00 00 48 8b bd b0 fe ff ff e8 8e 01 00 00 48 8d 35 ec 2d 00 00 48 89 c7 e8 5b 29 00 00 48 89 85 a0 fe ff ff e9 00 00 00 00 48 8b 85 a0 fe ff ff 48 89 85 d8 fe ff ff 48 83 bd d8 fe ff ff 00 0f 84 c4 00 00 00 e9 00 00 00 00 48 8b bd d8 fe ff ff e8 04 29 00 00 89 85 9c fe ff ff e9 00 00 00 00 8b 85 9c fe ff ff 83 f8 00 0f 95 c1 80 f1 ff f6 c1 01 0f 85 05 00 00 00 e9 75 00 00 00 48 8b 95 d8 fe ff ff 48 8d bd f0 fe ff ff be 00 01 00 00 e8 ca 28 00 00 48 89 85 90 fe ff ff e9 00 00 00 00 48 8b 85 90 fe ff ff 48 83 f8 00 0f 84 3b 00 00 00 48 8d b5 f0 fe ff ff 48 8b bd b8 fe ff ff }
        // curl call
        $s3 = "11101000010110101110100011010010110110101100101011011110111010101110100001000000011100100110000001100000010000000101101010011000010000000100010011010000111010001110100011100000111001100111010001011110010111101101101"
        $s4 = { 48 8b bd d8 fe ff ff e8 73 28 00 00 e9 00 00 00 00 e9 00 00 00 00 c6 85 e7 fe ff ff 01 f6 85 e7 fe ff ff 01 0f 85 0c 00 00 00 48 8b bd b8 fe ff ff e8 cb 27 00 00 48 8b 05 fc 2f 00 00 48 8b 00 48 8b 4d f8 48 39 c8 0f 85 32 00 00 00 48 8b 85 a8 fe ff ff 48 81 c4 80 01 00 }
    condition:
        uint32(0) == 0xFEEDFACF and filesize > 50KB and (($s1 and $s3) or ($s2 and $s4))
}
