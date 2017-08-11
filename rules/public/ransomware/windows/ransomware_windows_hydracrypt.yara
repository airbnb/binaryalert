rule ransomware_windows_hydracrypt
{
    meta:
        description = "HydraCrypt encrypts a victim’s files and appends the filenames with the extension “hydracrypt_ID_*"
        reference = "https://securingtomorrow.mcafee.com/mcafee-labs/hydracrypt-variant-of-ransomware-distributed-by-angler-exploit-kit/"
        author = "@fusionrace"
        md5 = "08b304d01220f9de63244b4666621bba"
    strings:
        $u0 = "oTraining" fullword ascii wide
        $u1 = "Stop Training" fullword ascii wide
        $u2 = "Play \"sound.wav\"" fullword ascii wide
        $u3 = "&Start Recording" fullword ascii wide
        $u4 = "7About record" fullword ascii wide
    condition:
        all of them
}
