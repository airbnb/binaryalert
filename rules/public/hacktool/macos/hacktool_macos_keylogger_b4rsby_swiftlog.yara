rule hacktool_macos_keylogger_b4rsby_swiftlog
{
    meta:
        description = "Dirty user level command line keylogger hacked together in Swift."
        reference = "https://github.com/b4rsby/SwiftLog"
        author = "@mimeframe"
    strings:
        $a1 = "You need to enable the keylogger in the System Prefrences" wide ascii
    condition:
        all of ($a*)
}
