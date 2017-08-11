rule hacktool_multi_responder_py
{
    meta:
        description = "Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server"
        reference = "http://www.c0d3xpl0it.com/2017/02/compromising-domain-admin-in-internal-pentest.html"
        author = "@fusionrace"
    strings:
        $s1 = "Poison all requests with another IP address than Responder's one." fullword ascii wide
        $s2 = "Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned." fullword ascii wide
        $s3 = "Enable answers for netbios wredir suffix queries. Answering to wredir will likely break stuff on the network." fullword ascii wide
        $s4 = "This option allows you to fingerprint a host that issued an NBT-NS or LLMNR query." fullword ascii wide
        $s5 = "Upstream HTTP proxy used by the rogue WPAD Proxy for outgoing requests (format: host:port)" fullword ascii wide
        $s6 = "31mOSX detected, -i mandatory option is missing" fullword ascii wide
        $s7 = "This option allows you to fingerprint a host that issued an NBT-NS or LLMNR query." fullword ascii wide
    condition:
        any of them
}
