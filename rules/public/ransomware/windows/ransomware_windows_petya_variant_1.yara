rule ransomware_windows_petya_variant_1
{
    meta:
        description = "Petya Ransomware new variant June 2017 using ETERNALBLUE"
        reference = "https://gist.github.com/vulnersCom/65fe44d27d29d7a5de4c176baba45759"
        author = "@fusionrace"
        md5 = "71b6a493388e7d0b40c83ce903bc6b04"
    strings:
        // instructions
        $s1 = "Ooops, your important files are encrypted." fullword ascii wide
        $s2 = "Send your Bitcoin wallet ID and personal installation key to e-mail" fullword ascii wide
        $s3 = "wowsmith123456@posteo.net. Your personal installation key:" fullword ascii wide
        $s4 = "Send $300 worth of Bitcoin to following address:" fullword ascii wide
        $s5 = "have been encrypted.  Perhaps you are busy looking for a way to recover your" fullword ascii wide
        $s6 = "need to do is submit the payment and purchase the decryption key." fullword ascii wide
    condition:
        any of them
}
