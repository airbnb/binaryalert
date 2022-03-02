rule MAL_Netfilter_Dropper_Jun_2021_1 {
   meta:
        description = "Detect the dropper of Netfilter rootkit"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/struppigel/status/1405483373280235520"
        date = "2020-06-18"
        hash1 = "a5c873085f36f69f29bb8895eb199d42ce86b16da62c56680917149b97e6dac"
        hash2 = "659e0d1b2405cadfa560fe648cbf6866720dd40bb6f4081d3dce2dffe20595d9"
        hash3 = "d0a03a8905c4f695843bc4e9f2dd062b8fd7b0b00103236b5187ff3730750540"
        tlp = "White"
        adversary = "Chinese APT Group"
   strings:
        $seq1 = { b8 ff 00 00 00 50 b8 00 00 00 00 50 8d 85 dd fe ff ff 50 e8 ?? 0d 00 00 83 c4 0c b8 00 00 00 00 88 85 dc fd ff ff b8 ff 00 00 00 50 b8 00 00 00 00 50 8d 85 dd fd ff ff 50 e8 ?? 0d 00 00 83 c4 0c b8 00 00 50 00 50 e8 ?? 0d 00 00 83 c4 04 89 85 d8 fd ff ff 8b 85 d8 fd ff ff 89 85 d4 fd ff ff b8 00 00 50 00 50 b8 00 00 00 00 50 8b 85 d8 fd ff ff 50 e8 ?? 0c 00 00 83 c4 0c 8b 45 0c 8b 8d d8 fd ff ff 89 08 b8 3c 00 00 00 50 b8 00 00 00 00 50 8d 85 98 fd ff ff 50 e8 ?? 0c 00 00 83 c4 0c b8 3c 00 00 00 89 85 98 fd ff ff 8d 85 98 fd ff ff 83 c0 10 8d 8d dc fe ff ff 89 08 8d 85 98 fd ff ff 83 c0 14 b9 00 01 00 00 89 08 8d 85 98 fd ff ff 83 c0 2c 8d 8d dc fd ff ff 89 08 8d 85 98 fd ff ff 83 c0 30 b9 00 01 00 00 89 08 b8 0a 31 40 00 50 e8 ?? 0c 00 00 89 85 94 fd ff ff b8 16 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0c 00 00 89 45 fc b8 28 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0c 00 00 89 45 f8 b8 36 31 40 00 50 8b 85 94 fd ff ff 50 e8 [2] 00 00 89 45 f4 b8 47 31 40 00 50 8b 85 94 fd ff ff 50 e8 [2] 00 00 89 45 f0 b8 58 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0b 00 00 89 45 ec b8 69 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0b 00 00 89 45 e8 b8 7a 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0b 00 00 89 45 e4 b8 8e 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0b 00 00 89 45 e0 8b 45 08 50 e8 ?? 0b 00 00 83 c4 04 8d 8d 98 fd ff ff 51 b9 00 00 00 00 51 50 8b 45 08 50 8b 45 fc ff d0 85 }
        $seq2 =  { b8 00 00 00 00 89 85 90 fd ff ff b8 00 00 00 00 89 85 8c fd ff ff b8 00 00 00 00 89 85 88 fd ff ff b8 00 00 00 00 89 85 84 fd ff ff b8 04 00 00 00 89 85 80 fd ff ff b8 00 00 00 00 88 85 7f f5 ff ff b8 00 08 00 00 50 b8 00 00 00 00 50 8d 85 80 f5 ff ff 50 e8 ?? 0b 00 00 83 c4 0c b8 00 00 00 00 50 b8 00 00 00 00 50 b8 00 00 00 00 50 b8 00 00 00 00 50 b8 9d 31 40 00 50 8b 45 f8 ff d0 89 85 90 fd ff ff 8b 85 }
        $s1 = "%s\\netfilter.sys" fullword ascii
        $s2 = "SYSTEM\\CurrentControlSet\\Services\\netfilter" fullword ascii
        $s3 = "\\\\.\\netfilter" fullword ascii
   condition:
        uint16(0) == 0x5a4d and filesize > 6KB and (all of ($seq*) or 2 of ($s*))
}
