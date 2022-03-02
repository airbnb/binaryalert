rule EnigmaStub
{
    meta:
        id = "nqfVjSZe90wUTGsVBo1SU"
        fingerprint = "7cc425b53393fbe7b1f4ad16d1fcb37f941199ff12341c74103c4cda14dd5e2c"
        version = "1.0"
        creation_date = "2020-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Enigma packer stub."
        category = "MALWARE"

    strings:
        $ = "Enigma anti-emulators plugin - GetProcAddress" ascii wide
        $ = "Enigma anti-debugger plugin - CheckRemoteDebuggerPresent" ascii wide
        $ = "Enigma anti-debugger plugin - IsDebuggerPresent" ascii wide
        $ = "Enigma Sandboxie Detect plugin" ascii wide
        $ = "Enigma_Plugin_Description" ascii wide
        $ = "Enigma_Plugin_About" ascii wide
        $ = "Enigma_Plugin_OnFinal" ascii wide
        $ = "EnigmaProtector" ascii wide
        $ = "Enigma_Plugin_OnInit" ascii wide

    condition:
        any of them
}