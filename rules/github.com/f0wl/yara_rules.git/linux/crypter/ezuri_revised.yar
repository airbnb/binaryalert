rule EzuriLoader_revised : LinuxMalware {

    meta:
        author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
        description = "Detects Ezuri Golang Loader/Crypter"
        reference = "https://cybersecurity.att.com/blogs/labs-research/malware-using-new-ezuri-memory-loader"
        date = "2021-01-09"
        tlp = "WHITE"
        hash1 = "ddbb714157f2ef91c1ec350cdf1d1f545290967f61491404c81b4e6e52f5c41f"
        hash2 = "751014e0154d219dea8c2e999714c32fd98f817782588cd7af355d2488eb1c80"

    strings:

        // This is a revised rule originally created by AT&T alien labs
        $a1 = "main.runFromMemory"
        $a2 = "main.aesDec"
        $a3 = "crypto/cipher.NewCFBDecrypter"
        $a4 = "/proc/self/fd/%d"
        $a5 = "/dev/null"
        
        // Additionally match on AES constants/SBox as proposed by @DuchyRE
        // https://en.wikipedia.org/wiki/Rijndael_S-box
        $aes = {A5 63 63 C6 84 7C 7C F8}
        $sbox = {63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76}

    condition:
        uint32(0) == 0x464c457f 
        and filesize < 20MB 
        and all of ($a*)
        and $aes and $sbox
}
