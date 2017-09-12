rule hacktool_macos_keylogger_logkext
{
    meta:
        description = "LogKext is an open source keylogger for Mac OS X, a product of FSB software."
        reference = "https://github.com/SlEePlEs5/logKext"
        author = "@mimeframe"
    strings:
        // daemon
        $a1 = "logKextPassKey" wide ascii
        $a2 = "Couldn't get system keychain:" wide ascii
        $a3 = "Error finding secret in keychain" wide ascii
        $a4 = "com_fsb_iokit_logKext" wide ascii
        // client
        $b1 = "logKext Password:" wide ascii
        $b2 = "Logging controls whether the daemon is logging keystrokes (default is on)." wide ascii
        // logkextkeygen
        $c1 = "logKextPassKey" wide ascii
        $c2 = "Error: couldn't create secAccess" wide ascii
        // logkext
        $d1 = "IOHIKeyboard" wide ascii
        $d2 = "Clear keyboards called with kextkeys" wide ascii
        $d3 = "Added notification for keyboard" wide ascii
    condition:
        3 of ($a*) or all of ($b*) or all of ($c*) or all of ($d*)
}
