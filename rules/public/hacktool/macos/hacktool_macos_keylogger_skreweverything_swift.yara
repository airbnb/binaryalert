rule hacktool_macos_keylogger_skreweverything_swift
{
    meta:
        description = "It is a simple and easy to use keylogger for macOS written in Swift."
        reference = "https://github.com/SkrewEverything/Swift-Keylogger"
        author = "@mimeframe"
    strings:
        $a1 = "Can't create directories!" wide ascii
        $a2 = "Can't create manager" wide ascii
        $a3 = "Can't open HID!" wide ascii
        $a4 = "PRINTSCREEN" wide ascii
        $a5 = "LEFTARROW" wide ascii
    condition:
        4 of ($a*)
}
