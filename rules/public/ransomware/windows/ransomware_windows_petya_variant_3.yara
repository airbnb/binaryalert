rule ransomware_windows_petya_variant_3
{
    meta:
        description = "Petya Ransomware new variant June 2017 using ETERNALBLUE"
        reference = "https://gist.github.com/vulnersCom/65fe44d27d29d7a5de4c176baba45759"
        author = "@fusionrace"
        md5 = "71b6a493388e7d0b40c83ce903bc6b04"
    strings:
        $s1 = "wevtutil cl Setup & wevtutil cl System" fullword wide
        $s2 = "fsutil usn deletejournal /D %c:" fullword wide
    condition:
        any of them
}
