rule aPLib_decompression
{     
	meta:
		description = "Detects aPLib decompression code often used in malware"
		author="@r3c0nst"
		date="2021-24-03"
		reference="https://ibsensoftware.com/files/aPLib-1.1.1.zip"

	strings:
		$pattern1 = { FC B2 80 31 DB A4 B3 02 }
		$pattern2 = { AC D1 E8 74 ?? 11 C9 EB }
		$pattern3 = { 73 0A 80 FC 05 73 ?? 83 F8 7F 77 }

	condition:
		filesize < 10MB and all of them
}
