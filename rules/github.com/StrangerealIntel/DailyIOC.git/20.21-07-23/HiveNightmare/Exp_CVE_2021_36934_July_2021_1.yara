rule Exp_CVE_2021_36934_July_2021_1
{
    meta:
        description = "Detect CVE_2021_36934 exploit (HiveNightmare)"
        author = "Arkbird_SOLG"
        date = "2021-07-23"
        reference = "https://github.com/GossiTheDog/HiveNightmare"
        hash1 = "0009d4950559b508353b951a314c5ac0aaae8161751017d3d4681dc805374eaa"
        hash2 = "7baab69f86b50199456c9208624dd16aeb0d18d8a6f2010ee6501a183476f12f"
        hash3 = "9035f88894a937892c63ac9a3c6c16301c7ecea7c11cf31d0fd24c39f17c8c2f"
        tlp = "white"
        adversary = "-"
    strings:
        $s1 = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" fullword wide
        $s2 = "Windows\\System32\\config\\SECURITY" fullword wide
        $s3 = "Windows\\System32\\config\\SYSTEM" fullword wide
        $s4 = "Windows\\System32\\config\\SAM" fullword wide
        $s5 = "SECURITY-" fullword wide
        $s6 = { 43 6f 75 6c 64 20 6e 6f 74 20 6f 70 65 6e 20 53 45 43 55 52 49 54 59 20 3a  }
        $s7 = { 7a d1 3f 99 5c 2d 21 79 f2 21 3d 00 58 ac 30 7a b5 d1 3f 7e 84 ff 62 3e cf 3d 3d }
    condition:
       uint16(0) == 0x5A4D  and filesize > 50KB and 5 of ($s*) 
}  
