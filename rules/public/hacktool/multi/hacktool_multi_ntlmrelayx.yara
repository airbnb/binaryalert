rule hacktool_multi_ntlmrelayx
{
    meta:
        description = "https://www.fox-it.com/en/insights/blogs/blog/inside-windows-network/"
        reference = "https://github.com/CoreSecurity/impacket/blob/master/examples/ntlmrelayx.py"
        author = "@mimeframe"
    strings:
        $a1 = "Started interactive SMB client shell via TCP" wide ascii
        $a2 = "Service Installed.. CONNECT!" wide ascii
        $a3 = "Done dumping SAM hashes for host:" wide ascii
        $a4 = "DA already added. Refusing to add another" wide ascii
        $a5 = "Domain info dumped into lootdir!" wide ascii
    condition:
        any of ($a*)
}
