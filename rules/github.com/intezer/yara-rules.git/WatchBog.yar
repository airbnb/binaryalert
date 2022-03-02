rule WatchBog_Cython
{	
	meta:
		copyright = "Intezer Labs"
		author = "Intezer Labs"
		reference = "https://www.intezer.com"
	
    strings:
	$a0 = "/tmp/.parttttzone"
	$a1 = "__pyx_kp_s_watchbog_dev"
	$a2 = "__pyx_k_watchbog_dev"
	$a3 = "__pyx_n_s_watchbog" 
	$a4 = "__pyx_k_watchbog"
	$b0 = "jail.BlueKeep"
	$b1 = "jail.Pwn"
	$b2 = "jail.Crack"
	$b3 = "jail.Solr"
	$b4 = "jail.Jira"
	$b5 = "jail.Couchdb"
	$b6 = "jail.Jenkins"
	$b7 = "jail.Laravel"
	$b8 = "jail.Bot"
    condition:
	any of ($a*) and 2 of ($b*)
}
