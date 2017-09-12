rule hacktool_macos_keylogger_dannvix
{
    meta:
        description = "A simple keylogger for macOS."
        reference = "https://github.com/dannvix/keylogger-osx"
        author = "@mimeframe"
    strings:
        $a1 = "/var/log/keystroke.log" wide ascii
        $a2 = "<forward-delete>" wide ascii
        $a3 = "<unknown>" wide ascii
    condition:
        all of ($a*)
}
