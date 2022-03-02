rule MAL_Milum_Jul_2021_1 {
   meta:
        description = "Detect Milum malware"
        author = "Arkbird_SOLG"
        reference = "https://securelist.com/wildpressure-targets-macos/103072/"
        date = "2021-07-08"
        // Build Jan 2021
        hash1 = "7eafb957c2e715e06489a979a185f75d7a9d502223c8aba36e7b6b8ead7d03b2"
        // Build Mar 2019
        hash2 = "86456ebf6b807e8253faf1262e7a2b673131c80174f6133b253b2e5f0da442a9"
        hash3 = "5e0226f37b861876ec38e4a1564a26e4af3022d869375bc0f09b8feea4cd9e1b"
        tlp = "White"
        adversary = "WildPressure"
   strings:
        // Defender check
        $s1 = { 52 00 4f 00 4f 00 54 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 43 00 65 00 6e 00 74 00 65 00 72 00 32 00 00 00 00 00 53 00 65 00 6c 00 65 00 63 00 74 00 20 [3-7] 20 00 46 00 72 00 6f 00 6d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 20 00 57 00 48 00 45 00 52 00 45 00 20 00 64 00 69 00 73 00 70 00 6c 00 61 00 79 00 4e 00 61 00 6d 00 65 00 20 00 3c 00 3e 00 27 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 27 }
        // VBS from 1.6.1
        $s2 = "c1VybCA9IHt1fQ0Kc1JlcXVlc3QgPSB7cH0NCkhUVFBQb3N0IHNVcmwsIHNSZXF1ZXN0DQpGdW5jdGlvbiBIVFRQUG9zdChzVXJsLCBzUmVxdWVzdCkNCiAgc2V0IG9IVFRQID0gQ3JlYXRlT2JqZWN0KCJNaWNyb3NvZnQuWE1MSFRUUCIpDQogIG9IVFRQLm9wZW4gIlBPU1QiLCBzVXJsLGZhbHNlDQogIG9IVFRQLnNldFJlcXVlc3RIZWFkZXIgIkNvbnRlbnQtVHlwZSIsICJhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQiDQogIG9IVFRQLnNldFJlcXVlc3RIZWFkZXIgIkNvbnRlbnQtTGVuZ3RoIiwgTGVuKHNSZXF1ZXN0KQ0KICBvSFRUUC5zZW5kIHNSZXF1ZXN0DQogIFdzY3JpcHQuRWNobyBvSFRUUC5yZXNwb25zZVRleHQNCiAgSFRUUFBvc3QgPSBvSFRUUC5yZXNwb25zZVRleHQNCiBFbmQgRnVuY3Rpb24=" fullword ascii
        // Handle ref
        $s3 = { 46 49 4c 45 20 48 41 4e 44 45 4c 20 4e 4f 54 20 46 4f 55 4e 44 00 00 00 4e 4f 20 44 61 74 61 00 }
        // Hardcoded header of json config (Base64)
        $s4 = { 28 00 77 00 73 00 33 00 32 00 29 00 65 00 79 00 4a 00 73 00 62 00 32 00 35 00 6e 00 64 00 32 00 46 00 70 00 64 00 43 00 49 00 36 00 49 00 6a 00 }
        // Run key condition
        $s5 = { 55 8b ec 6a ff 68 [3] 00 64 a1 00 00 00 00 50 83 ec 24 a1 [3] 00 33 c5 89 45 f0 ?? 57 50 8d 45 f4 64 a3 00 00 00 00 [8] b9 0f 00 00 00 89 4e }
        // Parsing op 
        $s6 = { 20 2f 63 20 [0-1] 46 4f 52 20 2f 6c 20 25 69 20 69 6e 20 28 31 2c 31 2c [1-4] 29 20 44 4f 20 49 46 20 4e 4f 54 20 45 58 49 53 54 20 22 00 22 29 }
        // DOM SecurityCenter
        $s7 = { 83 c4 0c 8d 95 44 fe ff ff 52 c7 85 44 fe ff ff 14 01 00 00 ff 15 [3] 00 83 bd 48 fe ff ff 06 7d 17 bf [3] 00 89 bd ?? fe ff ff c7 85 ?? fe ff ff [3] 00 eb 1a c7 85 ?? fe ff ff [3] 00 8b bd ?? fe ff ff c7 85 ?? fe ff ff [3] 00 }
        //Bonus -> Check PhysicalDrive
        $s8 = { 8b 45 08 50 68 bc 78 45 00 68 d0 78 45 00 8d 8d d0 fc ff ff 51 ff d6 83 c4 10 8b 3d a0 e0 44 00 8b 35 c4 e0 44 00 8d 64 }
   condition:
     uint16(0) == 0x5a4d and filesize > 40KB and 5 of ($s*)
}
