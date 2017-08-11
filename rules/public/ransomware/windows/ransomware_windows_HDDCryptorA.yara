rule ransomware_windows_HDDCryptorA
{
    meta:
        description = "The HDDCryptor ransomware encrypts local harddisks as well as resources in network shares via Server Message Block (SMB)"
        reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/bksod-by-ransomware-hddcryptor-uses-commercial-tools-to-encrypt-network-shares-and-lock-hdds/"
        author = "@fusionrace"
        md5 = "498bdcfb93d13fecaf92e96f77063abf"
    strings:
        // unique strings
        $u1 = "You are Hacked" fullword ascii wide
        $u2 = "Your H.D.D Encrypted , Contact Us For Decryption Key" nocase ascii wide
        $u3 = "start hard drive encryption..." ascii wide
        $u4 = "Your hard drive is securely encrypted" ascii wide
        // generic strings
        $g1 = "Wipe All Passwords?" ascii wide
        $g2 = "SYSTEM\\CurrentControlSet\\Services\\dcrypt\\config" ascii wide
        $g3 = "DiskCryptor" ascii wide
        $g4 = "dcinst.exe" fullword ascii wide
        $g5 = "dcrypt.exe" fullword ascii wide
        $g6 = "you can only use AES to encrypt the boot partition!" ascii wide
    condition:
        2 of ($u*) or 4 of ($g*)
}
