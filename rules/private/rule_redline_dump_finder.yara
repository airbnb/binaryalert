rule redline_dump_finder { 
    meta: 
        description = "Detects Redline Credential Dumps containing domains related to epicgames" 
        author = "Josh Hakala" 
		date = "2021-11-30" 
		hash1 = "62226f2a85f1ba35d91100b74197416e51f9ab5b8ff3ad6dbcc05b0423e08dd5"
	strings: 
		$red1 = "Telegram: https://t.me/REDLINESUPPORT" ascii wide nocase
		$dom1 = "epicgames.com" ascii wide nocase
condition: 
	all of ($red*) and 1 of ($dom*)
}