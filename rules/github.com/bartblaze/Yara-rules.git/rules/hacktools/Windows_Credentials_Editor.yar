rule Windows_Credentials_Editor
{
    meta:
        id = "3Q5yGnr66Sy8HikXBcYqKN"
        fingerprint = "2ba3672c391e1426f01f623538f85bc377eec8ff60eda61c1af70f191ab683a3"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Windows Credentials Editor (WCE), post-exploitation tool."
        category = "HACKTOOL"
        tool = "WINDOWS CREDENTIAL EDITOR"
        mitre_att = "S0005"
        reference = "https://www.ampliasecurity.com/research/windows-credentials-editor/"


    strings:
        $ = "Windows Credentials Editor" ascii wide
        $ = "Can't enumerate logon sessions!" ascii wide
        $ = "Cannot get PID of LSASS.EXE!" ascii wide
        $ = "Error: cannot dump TGT" ascii wide
        $ = "Error: Cannot extract auxiliary DLL!" ascii wide
        $ = "Error: cannot generate LM Hash." ascii wide
        $ = "Error: cannot generate NT Hash." ascii wide
        $ = "Error: Cannot open LSASS.EXE!." ascii wide
        $ = "Error in cmdline!." ascii wide
        $ = "Forced Safe Mode Error: cannot read credentials using 'safe mode'." ascii wide
        $ = "Reading by injecting code! (less-safe mode)" ascii wide
        $ = "username is too long!." ascii wide
        $ = "Using WCE Windows Service.." ascii wide
        $ = "Using WCE Windows Service..." ascii wide
        $ = "Warning: I will not be able to extract the TGT session key" ascii wide
        $ = "WCEAddNTLMCredentials" ascii wide
        $ = "wceaux.dll" ascii wide fullword
        $ = "WCEGetNTLMCredentials" ascii wide
        $ = "wce_ccache" ascii wide fullword
        $ = "wce_krbtkts" ascii wide fullword

    condition:
        3 of them
}