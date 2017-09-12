rule hacktool_macos_ptoomey3_keychain_dumper
{
    meta:
        description = "Keychain dumping utility."
        reference = "https://github.com/ptoomey3/Keychain-Dumper"
        author = "@mimeframe"
    strings:
        $a1 = "keychain_dumper" wide ascii
        $a2 = "/var/Keychains/keychain-2.db" wide ascii
        $a3 = "<key>keychain-access-groups</key>" wide ascii
        $a4 = "SELECT DISTINCT agrp FROM genp UNION SELECT DISTINCT agrp FROM inet" wide ascii
        $a5 = "dumpEntitlements" wide ascii
    condition:
        all of ($a*)
}
