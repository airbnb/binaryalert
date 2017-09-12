rule hacktool_macos_keylogger_roxlu_ofxkeylogger
{
    meta:
        description = "ofxKeylogger keylogger."
        reference = "https://github.com/roxlu/ofxKeylogger"
        author = "@mimeframe"
    strings:
        $a1 = "keylogger_init" wide ascii
        $a2 = "install_keylogger_hook function not found in dll." wide ascii
        $a3 = "keylogger_set_callback" wide ascii
    condition:
        all of ($a*)
}
