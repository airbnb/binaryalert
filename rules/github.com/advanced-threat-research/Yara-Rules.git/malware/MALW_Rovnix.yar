rule rovnix_downloader
{
	meta:

		description = "Rovnix downloader with sinkhole checks"
		author = "Intel Security"
		rule_version = "v1"
        malware_type = "downloader"
        malware_family = "Downloader:W32/Rovnix"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
		reference = "https://blogs.mcafee.com/mcafee-labs/rovnix-downloader-sinkhole-time-checks/"
	
	strings:

			$sink1= "control"
			$sink2 = "sink"
			$sink3 = "hole"
			$sink4= "dynadot"
			$sink5= "block"
			$sink6= "malw"
			$sink7= "anti"
			$sink8= "googl"
			$sink9= "hack"
			$sink10= "trojan"
			$sink11= "abuse"
			$sink12= "virus"
			$sink13= "black"
			$sink14= "spam"
			$boot= "BOOTKIT_DLL.dll"
			$mz = { 4D 5A }

	condition:
	
		$mz in (0..2) and
		all of ($sink*) and
		$boot
}
