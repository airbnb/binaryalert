rule hacktool_windows_moyix_creddump
{
    meta:
        description = "creddump is a python tool to extract credentials and secrets from Windows registry hives."
        reference = "https://github.com/moyix/creddump"
        author = "@mimeframe"
    strings:
        $a1 = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%" wide ascii
        $a2 = "0123456789012345678901234567890123456789" wide ascii
        $a3 = "NTPASSWORD" wide ascii
        $a4 = "LMPASSWORD" wide ascii
        $a5 = "aad3b435b51404eeaad3b435b51404ee" wide ascii
        $a6 = "31d6cfe0d16ae931b73c59d7e0c089c0" wide ascii
    condition:
        all of ($a*)
}
