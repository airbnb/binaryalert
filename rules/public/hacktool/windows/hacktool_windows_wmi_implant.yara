rule hacktool_windows_wmi_implant
{
    meta:
        description = "A PowerShell based tool that is designed to act like a RAT"
        reference = "https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html"
        author = "@fusionrace"
    strings:
        $s1 = "This really isn't applicable unless you are using WMImplant interactively." fullword ascii wide
        $s2 = "What command do you want to run on the remote system? >" fullword ascii wide
        $s3 = "Do you want to [create] or [delete] a string registry value? >" fullword ascii wide
        $s4 = "Do you want to run a WMImplant against a list of computers from a file? [yes] or [no] >" fullword ascii wide
        $s5 = "What is the name of the service you are targeting? >" fullword ascii wide
        $s6 = "This function enables the user to upload or download files to/from the attacking machine to/from the targeted machine" fullword ascii wide
        $s7 = "gen_cli - Generate the CLI command to execute a command via WMImplant" fullword ascii wide
        $s8 = "exit - Exit WMImplant" fullword ascii wide
        $s9 = "Lateral Movement Facilitation" fullword ascii wide
        $s10 = "vacant_system - Determine if a user is away from the system." fullword ascii wide
        $s11 = "Please provide the ProcessID or ProcessName flag to specify the process to kill!" fullword ascii wide
    condition:
        any of them
}
