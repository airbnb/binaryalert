import "pe"

rule hacktool_windows_mimikatz_sekurlsa
{
    meta:
        description = "Mimikatz credential dump tool"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "Airbnb CSIRT"
        SHA256_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        SHA256_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
    strings:
        $s1 = "dpapisrv!g_MasterKeyCacheList" fullword ascii wide
        $s2 = "lsasrv!g_MasterKeyCacheList" fullword ascii wide
        $s3 = "!SspCredentialList" ascii wide
        $s4 = "livessp!LiveGlobalLogonSessionList" fullword ascii wide
        $s5 = "wdigest!l_LogSessList" fullword ascii wide
        $s6 = "tspkg!TSGlobalCredTable" fullword ascii wide
    condition:
        all of them
}

rule hacktool_windows_mimikatz_modules
{
    meta:
        author = "Airbnb CSIRT"
        description = "Mimikatz credential dump tool: Modules"
        reference = "https://github.com/gentilkiwi/mimikatz"
        md5_1 = "0c87c0ca04f0ab626b5137409dded15ac66c058be6df09e22a636cc2bcb021b8"
        md5_2 = "0c91f4ca25aedf306d68edaea63b84efec0385321eacf25419a3050f2394ee3b"
        md5_3 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        md5_4 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
        md5_5 = "0fee62bae204cf89d954d2cbf82a76b771744b981aef4c651caab43436b5a143"
    strings:
        $s1 = "mimilib" fullword ascii wide
        $s2 = "mimidrv" fullword ascii wide
        $s3 = "mimilove" fullword ascii wide
    condition:
        any of them
}

rule hacktool_windows_mimikatz_files
{
    meta:
        author = "Airbnb CSIRT"
        description = "Mimikatz credential dump tool: Files"
        reference = "https://github.com/gentilkiwi/mimikatz"
        md5_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        md5_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
    strings:
        $s1 = "kiwifilter.log" fullword wide
        $s2 = "kiwissp.log" fullword wide
        $s3 = "mimilib.dll" fullword ascii wide
    condition:
        any of them
}

rule hacktool_windows_mimikatz_copywrite
{
    meta:
        description = "Mimikatz credential dump tool: Author copywrite"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "Airbnb CSIRT"
        md5_1 = "0c87c0ca04f0ab626b5137409dded15ac66c058be6df09e22a636cc2bcb021b8"
        md5_2 = "0c91f4ca25aedf306d68edaea63b84efec0385321eacf25419a3050f2394ee3b"
        md5_3 = "0fee62bae204cf89d954d2cbf82a76b771744b981aef4c651caab43436b5a143"
        md5_4 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
        md5_5 = "09c542ff784bf98b2c4899900d4e699c5b2e2619a4c5eff68f6add14c74444ca"
        md5_6 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
    strings:
        $s1 = "Kiwi en C" fullword ascii wide
        $s2 = "Benjamin DELPY `gentilkiwi`" fullword ascii wide
        $s3 = "http://blog.gentilkiwi.com/mimikatz" fullword ascii wide
        $s4 = "Build with love for POC only" fullword ascii wide
        $s5 = "gentilkiwi (Benjamin DELPY)" fullword wide
        $s6 = "KiwiSSP" fullword wide
        $s7 = "Kiwi Security Support Provider" fullword wide
        $s8 = "kiwi flavor !" fullword wide
    condition:
        any of them
}

rule hacktool_windows_mimikatz_errors
{
    meta:
        description = "Mimikatz credential dump tool: Error messages"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "Airbnb CSIRT"
        md5_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        md5_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
    strings:
        $s1 = "[ERROR] [LSA] Symbols" fullword ascii wide
        $s2 = "[ERROR] [CRYPTO] Acquire keys" fullword ascii wide
        $s3 = "[ERROR] [CRYPTO] Symbols" fullword ascii wide
        $s4 = "[ERROR] [CRYPTO] Init" fullword ascii wide
    condition:
        all of them
}

rule hacktool_windows_ncc_wmicmd
{
    meta:
        description = "Command shell wrapper for WMI"
        reference = "https://github.com/nccgroup/WMIcmd"
        author = "Airbnb CSIRT"
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

rule hacktool_windows_hot_potato
{
    meta:
        description = "https://foxglovesecurity.com/2016/01/16/hot-potato/"
        reference = "https://github.com/foxglovesec/Potato"
        author = "Airbnb CSIRT"
    strings:
        $a1 = "Parsing initial NTLM auth..." wide ascii
        $a2 = "Got PROPFIND for /test..." wide ascii
        $a3 = "Starting NBNS spoofer..." wide ascii
        $a4 = "Exhausting UDP source ports so DNS lookups will fail..." wide ascii
        $a5 = "Usage: potato.exe -ip" wide ascii
    condition:
        any of ($a*)
}

rule hacktool_windows_rdp_cmd_delivery
{
    meta:
        description = "Delivers a text payload via RDP (rubber ducky)"
        reference = "https://github.com/nopernik/mytools/blob/master/rdp-cmd-delivery.sh"
        author = "Airbnb CSIRT"
    strings:
        $s1 = "Usage: rdp-cmd-delivery.sh OPTIONS" ascii wide
        $s2 = "[--tofile 'c:\\test.txt' local.ps1 #will copy contents of local.ps1 to c:\\test.txt" ascii wide
        $s3 = "-cmdfile local.bat                #will execute everything from local.bat" ascii wide
        $s4 = "To deliver powershell payload, use '--cmdfile script.ps1' but inside powershell console" ascii wide
    condition:
        any of them
}

rule hacktool_windows_WMImplant
{
    meta:
        description = "A PowerShell based tool that is designed to act like a RAT"
        reference = "https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html"
        author = "Airbnb CSIRT"
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
