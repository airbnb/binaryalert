rule hacktool_windows_rdp_cmd_delivery
{
    meta:
        description = "Delivers a text payload via RDP (rubber ducky)"
        reference = "https://github.com/nopernik/mytools/blob/master/rdp-cmd-delivery.sh"
        author = "@fusionrace"
    strings:
        $s1 = "Usage: rdp-cmd-delivery.sh OPTIONS" ascii wide
        $s2 = "[--tofile 'c:\\test.txt' local.ps1 #will copy contents of local.ps1 to c:\\test.txt" ascii wide
        $s3 = "-cmdfile local.bat                #will execute everything from local.bat" ascii wide
        $s4 = "To deliver powershell payload, use '--cmdfile script.ps1' but inside powershell console" ascii wide
    condition:
        any of them
}
