rule hacktool_multi_ncc_ABPTTS
{
    meta:
        description = "Allows for TCP tunneling over HTTP"
        reference = "https://github.com/nccgroup/ABPTTS"
        author = "@mimeframe"
    strings:
        $s1 = "---===[[[ A Black Path Toward The Sun ]]]===---" ascii wide
        $s2 = "https://vulnerableserver/EStatus/" ascii wide
        $s3 = "Error: no ABPTTS forwarding URL was specified. This utility will now exit." ascii wide
        // access key
        $s4 = "tQgGur6TFdW9YMbiyuaj9g6yBJb2tCbcgrEq" fullword ascii wide
        // encryption key
        $s5 = "63688c4f211155c76f2948ba21ebaf83" fullword ascii wide
        // log file
        $s6 = "ABPTTSClient-log.txt" fullword ascii wide
    condition:
        any of them
}
