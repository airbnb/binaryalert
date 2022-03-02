rule RANSOM_wastedlocker
{
    meta:
    
        description = "Rule to detect unpacked samples of WastedLocker"
        author = "McAfee ATR Team"
        date = "2020-07-27"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/WastedLocker"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        hash1 = "ae255679f487e2e9075ffd5e8c7836dd425229c1e3bd40cfc46fbbceceec7cf4"
    
    strings:

        $pattern_0 = { 8d45fc 50 53 53 6a19 ff75f8 }
        $pattern_1 = { 66833b00 8bf3 0f8485000000 8b7d10 8b472c 85c0 7410 }
        $pattern_2 = { e8???????? 8b4d08 8b4518 8d0441 6683600200 83c40c 837d1400 }
        $pattern_3 = { 8701 e9???????? 8bc7 5f 5e 5b }
        $pattern_4 = { 8bf8 3bfb 742f 53 8d45fc 50 56 }
        $pattern_5 = { 6a10 8d45f0 6a00 50 e8???????? 83c40c 5e }
        $pattern_6 = { 5f 5d c20800 55 8bec }
        $pattern_7 = { 8d7e04 ff15???????? 85c0 8945e8 740e 2b4510 }
        $pattern_8 = { ff15???????? 8b45dc 8b4dbc 69c00d661900 055ff36e3c 8945dc }
        $pattern_9 = { 8b4d08 8b19 03d8 f7d0 c1c60f 03f2 0bc6 }
   
    condition:

        7 of them and
        filesize < 1806288
}
