rule AgeLocker
{
	meta:
		copyright = "Intezer Labs"
		author = "Intezer Labs"
		reference = "https://www.intezer.com"

    strings:
        $a0 = "agelocker.go"
        $a1 = "filippo.io/age/age.go"
        $b0 = "main.encrypt"
        $b2 = "main.stringInSlice"
        $b3 = "main.create_message"
        $b4 = "main.fileExists"


    condition:
        any of ($a*) and any of ($b*)
}
