rule RANSOM_mountlocker
{
   meta:

      description = "Rule to detect Mount Locker ransomware"
      author = "McAfee ATR Team"
      date = "2020-09-25"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransomware:W32/MountLocker"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash1 = "4b917b60f4df6d6d08e895d179a22dcb7c38c6a6a6f39c96c3ded10368d86273"
      hash2 = "f570d5b17671e6f3e56eae6ad87be3a6bbfac46c677e478618afd9f59bf35963"
    
    strings:

        $s1 = {63 69 64 3d 25 43 4c 49 45 4e 54 5f 49 44}
        $s2 = {7a 73 61 33 77 78 76 62 62 37 67 76 36 35 77 6e 6c 37 6c 65 72 73 6c 65 65 33 63 37 69 32 37 6e 64 71 67 68 71 6d 36 6a 74 32 70 72 69 76 61 32 71 63 64 70 6f 6e 61 64 2e 6f 6e 69 6f 6e}
        $s3 = {36 6d 6c 7a 61 68 6b 63 37 76 65 6a 79 74 70 70 62 71 68 71 6a 6f 75 34 69 70 66 74 67 73 33 67 69 7a 6f 66 32 78 34 7a 6b 6c 62 6c 6c 69 61 79 68 73 71 62 33 77 61 64 2e 6f 6e 69 6f 6e}


    condition:

        uint16(0) == 0x5a4d and
        filesize < 300KB and
        ($s1 and
        $s2) or
        ($s1 and
        $s3) or
        $s1 
}
