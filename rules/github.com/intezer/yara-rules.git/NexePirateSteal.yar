rule nexe_piratesteal {
	meta:
        author = "Intezer"
        description = "Hunting for Nexe compiled PirateStealer Dropper"
        tlp = "white"
  strings:
		$nexe_str = "process.__nexe = {\"resources\""
        $steal_str0 = "file.includes(\"iscord\")"
        $steal_str1 = "\\app-*\\modules\\discord_desktop_core-*\\discord_desktop_core\\index.js"
		$steal_str2 = "pwnBetterDiscord"
  condition:
    (uint16(0) == 0x5A4D and $nexe_str and 2 of ($steal_str*))
}
