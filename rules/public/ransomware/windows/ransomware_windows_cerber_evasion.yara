rule ransomware_windows_cerber_evasion
{
    meta:
        description = "Cerber Ransomware: Evades detection by machine learning applications"
        reference_1 = "http://blog.trendmicro.com/trendlabs-security-intelligence/cerber-starts-evading-machine-learning/"
        reference_2 = "http://www.darkreading.com/vulnerabilities---threats/cerber-ransomware-now-evades-machine-learning/d/d-id/1328506"
        author = "@fusionrace"
        md5 = "bc62b557d48f3501c383f25d014f22df"
    strings:
        $s1 = "38oDr5.vbs" fullword ascii wide
        $s2 = "8ivq.dll" fullword ascii wide
        $s3 = "jmsctls_progress32" fullword ascii wide
    condition:
        all of them
}
