rule revil_linux : Ransomware {

    meta:
        author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
        description = "Detects the Linux version of REvil Ransomware with ESXI capabilities"
        date = "2021-07-05"
        reference = "https://cybersecurity.att.com/blogs/labs-research/revils-new-linux-version"
        tlp = "WHITE"
        hash1 = "3d375d0ead2b63168de86ca2649360d9dcff75b3e0ffa2cf1e50816ec92b3b7d"
        hash2 = "ea1872b2835128e3cb49a0bc27e4727ca33c4e6eba1e80422db19b505f965bc4"
        hash3 = "796800face046765bd79f267c56a6c93ee2800b76d7f38ad96e5acb92599fcd4"
        hash4 = "d6762eff16452434ac1acc127f082906cc1ae5b0ff026d0d4fe725711db47763"

    strings:

        // Shell command to kill all running VMs on the ESXI server: esxcli --formatter=csv --format-param=fields=="WorldID,DisplayName" vm process list | awk -F "\"*,\"*" '{system("esxcli vm process kill --type=force --world-id=" $1)}'
        $vmKill = {657378636C69202D2D666F726D61747465723D637376202D2D666F726D61742D706172616D3D6669656C64733D3D22576F726C6449442C446973706C61794E616D652220766D2070726F63657373206C697374207C2061776B202D4620225C222A2C5C222A2220277B73797374656D2822657378636C6920766D2070726F63657373206B696C6C202D2D747970653D666F726365202D2D776F726C642D69643D22202431297D27}
        
        $a1 = "Usage example: elf.exe --path /vmfs/ --threads 5 " fullword ascii
        $a2 = "!!!BY DEFAULT THIS SOFTWARE USES 50 THREADS!!!" fullword ascii
        $a3 = "[%s] already encrypted" fullword ascii
        $a4 = "Error decoding user_id %d " fullword ascii
        $a5 = " without --path encrypts current dir" fullword ascii
        $a6 = "File [%s] was encrypted" fullword ascii
        $a7 = "File [%s] was NOT encrypted" fullword ascii
        $a8 = "Using silent mode, if you on esxi - stop VMs manualy" fullword ascii
        $a9 = "Error decoding master_pk %d " fullword ascii
        $a10 = "Error decoding sub_id %d " fullword ascii
        $a11 = "Error decoding note_body %d " fullword ascii

    condition:
        uint32(0) == 0x464c457f 
        and filesize < 500KB 
        and 7 of them
}
