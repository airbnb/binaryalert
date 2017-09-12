rule hacktool_macos_keylogger_caseyscarborough
{
    meta:
        description = "A simple and easy to use keylogger for macOS."
        reference = "https://github.com/caseyscarborough/keylogger"
        author = "@mimeframe"
    strings:
        $a1 = "/var/log/keystroke.log" wide ascii
        $a2 = "ERROR: Unable to create event tap." wide ascii
        $a3 = "Keylogging has begun." wide ascii
        $a4 = "ERROR: Unable to open log file. Ensure that you have the proper permissions." wide ascii
    condition:
        2 of ($a*)
}
