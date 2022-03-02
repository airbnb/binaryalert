rule SUSP_activex_link
{
	meta:
		author      = "imp0rtp3"
		description = "Suspicious ActiveX link as observed in Candiru phishing documents. The YARA is for the Activex1.xml in the DOC"
		reference   = "https://blog.google/threat-analysis-group/how-we-protect-users-0-day-attacks"
		sha256      = "656d19186795280a068fcb97e7ef821b55ad3d620771d42ed98d22ee3c635e67"
		sha256      = "851bf4ab807fc9b29c9f6468c8c89a82b8f94e40474c6669f105bce91f278fdb"
	strings:
		$a1 = "ax:ocx ax:classid=\"{EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B}\""
		$a2 = "ax:ocxPr ax:name=\"Location\" ax:value=\"http"
		$b1 = "ax:persistence=\"persistPropertyBag\""
		$b2 = "ax:name=\"HideFileNames\""
		$b3 = "ax:name=\"Transparent\""
		$b4 = "ax:name=\"RegisterAsBrowser\""
		$b5 = "ax:name=\"NoClientEdge\""

	condition:
		filesize < 50000 and all of ($a*) and 3 of ($b*)

}
