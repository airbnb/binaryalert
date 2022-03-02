rule RAN_Astrolocker_May_2021_1 {
   meta:
        description = "Detect the Astrolocker ransomware"
        author = "Arkbird_SOLG"
        // thanks to @dragan_security for his help
        reference = "Internal Research"
        date = "2020-05-12"
        hash1 = "7fe1686f4afb9907f880a5e77bf30bc00fae71980f57ca70b60b7b1716456a2f"
        hash2 = "b26749b17ca691328ba67ee49d4d9997c101966c607ab578afad204459b7bf8f"
        tlp = "White"
        adversary = "-"
        level = "Experimental"
   strings:      
        $seq_Mar_2021_1 = { 6a 00 6a 00 ff 15 88 60 41 00 81 3d cc e6 b8 02 57 0f 00 00 8b 0d b4 c4 41 00 8b 15 b8 c4 41 00 a1 bc c4 41 00 89 4c 24 2c 89 54 24 20 89 44 24 24 75 14 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 28 60 41 00 8b 2d a8 60 41 00 c7 44 24 1c 20 00 00 00 8d 9b 00 00 00 00 8b 54 24 18 8b ce c1 e1 04 03 4c 24 20 8b c6 c1 e8 05 89 4c 24 14 8d 0c 32 89 44 24 10 8b 44 24 24 01 44 24 10 31 4c 24 14 81 3d cc e6 b8 02 f5 03 00 00 c7 05 0c da b8 02 36 06 ea e9 75 08 6a 00 ff 15 5c 60 41 00 8b 4c 24 14 31 4c 24 10 83 3d cc e6 b8 02 42 75 30 6a 00 6a 00 6a 00 ff d5 6a 30 8d 54 24 3c 6a 00 52 c7 44 24 40 00 00 00 00 e8 5a 5e ff ff 83 c4 0c 6a 00 8d 44 24 38 50 6a 00 ff 15 00 60 41 00 2b 5c 24 10 8b cb c1 e1 04 81 3d cc e6 b8 02 8c 07 00 00 89 4c 24 14 75 09 6a 00 6a 00 e8 d2 eb fe ff }
        $seq_Apr_2021_1 = { 89 44 24 38 48 8b 05 78 4e 00 00 48 89 05 b9 9e 00 00 48 8b 05 52 4e 00 00 48 89 05 b3 9e 00 00 48 8b 05 4c 4e 00 00 48 89 05 ad 9e 00 00 48 8b 05 46 4e 00 00 48 89 05 a7 9e 00 00 8b 05 51 9e }
   condition:
         uint16(0) == 0x5a4d and filesize > 30KB and 1 of ($seq*)     
}
