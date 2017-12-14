rule hacktool_windows_cobaltstrike_powershell
{
    meta:
        description = "Detection of the PowerShell payloads from Cobalt Strike"
        reference = "https://www.cobaltstrike.com/help-payload-generator"
        author = "@javutin, @joseselvi"
    strings:
        $ps1 = "Set-StrictMode -Version 2"
        $ps2 = "func_get_proc_address"
        $ps3 = "func_get_delegate_type"
        $ps4 = "FromBase64String"
        $ps5 = "VirtualAlloc"
        $ps6 = "var_code"
        $ps7 = "var_buffer"
        $ps8 = "var_hthread"

    condition:
        $ps1 at 0 and
        filesize < 1000KB and
        all of ($ps*)
}