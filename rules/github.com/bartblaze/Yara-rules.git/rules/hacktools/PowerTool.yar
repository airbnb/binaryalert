import "pe"

rule PowerTool
{
    meta:
        id = "1xsVS7M8rwYUf81xA2UjIE"
        fingerprint = "0244bd12a172270bedd0165ea5fd95ee4176e46a0fb501e0888281927fbbea4b"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PowerTool, sometimes used by attackers to disable security software."
        category = "MALWARE"
        malware = "POWERTOOL"
        reference = "https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml"


    strings:
        $ = "C:\\dev\\pt64_en\\Release\\PowerTool.pdb" ascii wide
        $ = "Detection may be stuck, First confirm whether the device hijack in [Disk trace]" ascii wide
        $ = "SuspiciousDevice Error reading MBR(Kernel Mode) !" ascii wide
        $ = "Modify kill process Bug." ascii wide
        $ = "Chage language nedd to restart PowerTool" ascii wide
        $ = ".?AVCPowerToolApp@@" ascii wide
        $ = ".?AVCPowerToolDlg@@" ascii wide

    condition:
        any of them
}