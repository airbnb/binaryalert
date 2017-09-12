rule hacktool_macos_manwhoami_mmetokendecrypt
{
    meta:
        description = "This program decrypts / extracts all authorization tokens on macOS / OS X / OSX."
        reference = "https://github.com/manwhoami/MMeTokenDecrypt"
        author = "@mimeframe"
    strings:
        $a1 = "security find-generic-password -ws 'iCloud'" wide ascii
        $a2 = "ERROR getting iCloud Decryption Key" wide ascii
        $a3 = "Could not find MMeTokenFile. You can specify the file manually." wide ascii
        $a4 = "Decrypting token plist ->" wide ascii
        $a5 = "Successfully decrypted token plist!" wide ascii
    condition:
        3 of ($a*)
}
