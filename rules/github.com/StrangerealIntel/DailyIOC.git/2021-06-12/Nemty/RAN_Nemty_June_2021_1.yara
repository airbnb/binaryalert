rule RAN_Nemty_June_2021_1 {
   meta:
        description = "Detect Nemty ransomware"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-06-12"
        hash1 = "45e35c9b095871fbc9b85afff4e79dd36b7812b96a302e1ccc65ce7668667fe6"
        hash2 = "511fee839098dfa28dd859ffd3ece5148be13bfb83baa807ed7cac2200103390"
        hash3 = "74b7a1da50ce44b640d84422bb3f99e2f338cc5d5be9ef5f1ad03c8e947296c3"
        tlp = "white"
        adversary = "RAAS"
   strings:      
            $s1 = { 83 f8 1a 0f 8d [2] 00 00 [0-1] 89 4c 24 [1-2] 89 54 24 [1-2] 89 ?? 24 [1-15] 00 00 00}
            $s2 = { 5a 4c 49 42 00 00 00 00 00 00 01 ?? 78 01 54 8f [3] 40 [2] cf }
            $s3 = { 4c 24 [1-2] 89 54 24 [1-2] 89 ?? 24 [12-25] 00 81 }
            $s4 = { ff ff [0-1] 8d 05 [3] 00 [0-1] 89 04 24 [0-1] c7 44 24 ?? 02 00 00 00 e8 [2] ff ff e8 [2] ff ff [0-1] 8b 4c 24 }
    condition:
            uint16(0) == 0x5a4d and filesize > 500KB and all of ($s*) 
}
