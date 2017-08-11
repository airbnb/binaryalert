rule ransomware_windows_zcrypt
{
    meta:
        description = "Zcrypt will encrypt data and append the .zcrypt extension to the filenames"
        reference = "https://blog.malwarebytes.com/threat-analysis/2016/06/zcrypt-ransomware/"
        author = "@fusionrace"
        md5 = "d1e75b274211a78d9c5d38c8ff2e1778"
    strings:
        // unique strings
        $u1 = "How to Buy Bitcoins" ascii wide
        $u2 = "ALL YOUR PERSONAL FILES ARE ENCRYPTED" ascii wide
        $u3 = "Click Here to Show Bitcoin Address" ascii wide
        $u4 = "MyEncrypter2.pdb" fullword ascii wide
        // generic strings
        $g1 = ".p7b" fullword ascii wide
        $g2 = ".p7c" fullword ascii wide
        $g3 = ".pdd" fullword ascii wide
        $g4 = ".pef" fullword ascii wide
        $g5 = ".pem" fullword ascii wide
        $g6 = "How to decrypt files.html" fullword ascii wide
    condition:
        any of ($u*) or all of ($g*)
}
