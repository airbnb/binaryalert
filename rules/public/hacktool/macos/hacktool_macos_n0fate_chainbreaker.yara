rule hacktool_macos_n0fate_chainbreaker
{
    meta:
        description = "chainbreaker can extract user credential in a Keychain file with Master Key or user password in forensically sound manner."
        reference = "https://github.com/n0fate/chainbreaker"
        author = "@mimeframe"
    strings:
        $a1 = "[!] Private Key Table is not available" wide ascii
        $a2 = "[!] Public Key Table is not available" wide ascii
        $a3 = "[-] Decrypted Private Key" wide ascii
    condition:
        all of ($a*)
}
