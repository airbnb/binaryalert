import "pe"

rule hacktool_multi_jtesta_ssh_mitm
{
    meta:
        description = "intercepts ssh connections to capture credentials"
        reference = "https://github.com/jtesta/ssh-mitm"
        author = "Airbnb CSIRT"
    strings:
        $a1 = "INTERCEPTED PASSWORD:" wide ascii
        $a2 = "more sshbuf problems." wide ascii
    condition:
        all of ($a*)
}

rule hacktool_multi_masscan
{
    meta:
        description = "masscan is a performant port scanner, it produces results similar to nmap"
        reference = "https://github.com/robertdavidgraham/masscan"
        author = "Airbnb CSIRT"
    strings:
        $a1 = "EHLO masscan" fullword wide ascii
        $a2 = "User-Agent: masscan/" wide ascii
        $a3 = "/etc/masscan/masscan.conf" fullword wide ascii
        $b1 = "nmap(%s): unsupported. This code will never do DNS lookups." wide ascii
        $b2 = "nmap(%s): unsupported, we do timing WAY different than nmap" wide ascii
        $b3 = "[hint] I've got some local priv escalation 0days that might work" wide ascii
        $b4 = "[hint] VMware on Macintosh doesn't support masscan" wide ascii
    condition:
        all of ($a*) or any of ($b*)
}

rule hacktool_multi_ntlmrelayx
{
    meta:
        description = "https://www.fox-it.com/en/insights/blogs/blog/inside-windows-network/"
        reference = "https://github.com/CoreSecurity/impacket/blob/master/examples/ntlmrelayx.py"
        author = "Airbnb CSIRT"
    strings:
        $a1 = "Started interactive SMB client shell via TCP" wide ascii
        $a2 = "Service Installed.. CONNECT!" wide ascii
        $a3 = "Done dumping SAM hashes for host:" wide ascii
        $a4 = "DA already added. Refusing to add another" wide ascii
        $a5 = "Domain info dumped into lootdir!" wide ascii
    condition:
        any of ($a*)
}

rule hacktool_multi_bloodhound_owned
{
    meta:
        description = "Bloodhound: Custom queries to document a compromise, find collateral spread of owned nodes, and visualize deltas in privilege gains"
        reference = "https://github.com/porterhau5/BloodHound-Owned/"
        author = "Airbnb CSIRT"
    strings:
        $s1 = "Find all owned Domain Admins" fullword ascii wide
        $s2 = "Find Shortest Path from owned node to Domain Admins" fullword ascii wide
        $s3 = "List all directly owned nodes" fullword ascii wide
        $s4 = "Set owned and wave properties for a node" fullword ascii wide
        $s5 = "Find spread of compromise for owned nodes in wave" fullword ascii wide
        $s6 = "Show clusters of password reuse" fullword ascii wide
        $s7 = "Something went wrong when creating SharesPasswordWith relationship" fullword ascii wide
        $s8 = "reference doc of custom Cypher queries for BloodHound" fullword ascii wide
        $s9 = "Created SharesPasswordWith relationship between" fullword ascii wide
        $s10 = "Skipping finding spread of compromise due to" fullword ascii wide
    condition:
        any of them
}

rule hacktool_multi_pyrasite_py
{
    meta:
        description = "A tool for injecting arbitrary code into running Python processes."
        reference = "https://github.com/lmacken/pyrasite"
        author = "Airbnb CSIRT"
    strings:
        $s1 = "WARNING: ptrace is disabled. Injection will not work." fullword ascii wide
        $s2 = "A payload that connects to a given host:port and receives commands" fullword ascii wide
        $s3 = "A reverse Python connection payload." fullword ascii wide
        $s4 = "pyrasite - inject code into a running python process" fullword ascii wide
        $s5 = "The ID of the process to inject code into" fullword ascii wide
        $s6 = "This file is part of pyrasite." fullword ascii wide
        $s7 = "https://github.com/lmacken/pyrasite" fullword ascii wide
        $s8 = "Setup a communication socket with the process by injecting" fullword ascii wide
        $s9 = "a reverse subshell and having it connect back to us." fullword ascii wide
        $s10 = "Write out a reverse python connection payload with a custom port" fullword ascii wide
        $s11 = "Wait for the injected payload to connect back to us" fullword ascii wide
        $s12 = "PyrasiteIPC" fullword ascii wide
        $s13 = "A reverse Python shell that behaves like Python interactive interpreter." fullword ascii wide
        $s14 = "pyrasite cannot establish reverse" fullword ascii wide
    condition:
        any of them
}

rule hacktool_multi_responder_py
{
    meta:
        description = "Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server"
        reference = "http://www.c0d3xpl0it.com/2017/02/compromising-domain-admin-in-internal-pentest.html"
        author = "Airbnb CSIRT"
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

rule hacktool_multi_ncc_ABPTTS
{
    meta:
        description = "Allows for TCP tunneling over HTTP"
        reference = "https://github.com/nccgroup/ABPTTS"
        author = "Airbnb CSIRT"
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
