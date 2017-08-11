rule ransomware_windows_powerware_locky
{
    meta:
        description = "PowerWare Ransomware"
        reference = "https://researchcenter.paloaltonetworks.com/2016/07/unit42-powerware-ransomware-spoofing-locky-malware-family/"
        author = "@fusionrace"
        md5 = "3433a4da9d8794709630eb06afd2b8c1"
    strings:
        // unpacks the powershell script
        $s0 = "ScriptRunner.dll" fullword ascii wide
        // debug file
        $s1 = "ScriptRunner.pdb" fullword ascii wide
        // dropped powershell script
        $s2 = "fixed.ps1" fullword ascii wide
    condition:
        all of them
}
