rule hacktool_windows_ncc_wmicmd
{
    meta:
        description = "Command shell wrapper for WMI"
        reference = "https://github.com/nccgroup/WMIcmd"
        author = "@mimeframe"
    strings:
        $a1 = "Need to specify a username, domain and password for non local connections" wide ascii
        $a2 = "WS-Management is running on the remote host" wide ascii
        $a3 = "firewall (if enabled) allows connections" wide ascii
        $a4 = "WARNING: Didn't see stdout output finished marker - output may be truncated" wide ascii
        $a5 = "Command sleep in milliseconds - increase if getting truncated output" wide ascii
        $b1 = "0x800706BA" wide ascii
        $b2 = "NTLMDOMAIN:" wide ascii
        $b3 = "cimv2" wide ascii
    condition:
        any of ($a*) or all of ($b*)
}
