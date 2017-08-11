rule hacktool_multi_masscan
{
    meta:
        description = "masscan is a performant port scanner, it produces results similar to nmap"
        reference = "https://github.com/robertdavidgraham/masscan"
        author = "@mimeframe"
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
