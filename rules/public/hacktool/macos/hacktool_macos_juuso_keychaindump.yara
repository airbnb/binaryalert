rule hacktool_macos_juuso_keychaindump
{
    meta:
        description = "For reading OS X keychain passwords as root."
        reference = "https://github.com/juuso/keychaindump"
        author = "@mimeframe"
    strings:
        $a1 = "[-] Too many candidate keys to fit in memory" wide ascii
        $a2 = "[-] Could not allocate memory for key search" wide ascii
        $a3 = "[-] Too many credentials to fit in memory" wide ascii
        $a4 = "[-] The target file is not a keychain file" wide ascii
        $a5 = "[-] Could not find the securityd process" wide ascii
        $a6 = "[-] No root privileges, please run with sudo" wide ascii
    condition:
        4 of ($a*)
}
