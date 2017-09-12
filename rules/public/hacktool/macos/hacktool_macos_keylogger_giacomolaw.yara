rule hacktool_macos_keylogger_giacomolaw
{
    meta:
        description = "A simple keylogger for macOS."
        reference = "https://github.com/GiacomoLaw/Keylogger"
        author = "@mimeframe"
    strings:
        $a1 = "ERROR: Unable to access keystroke log file. Please make sure you have the correct permissions." wide ascii
        $a2 = "ERROR: Unable to create event tap." wide ascii
        $a3 = "Keystrokes are now being recorded" wide ascii
    condition:
        2 of ($a*)
}
