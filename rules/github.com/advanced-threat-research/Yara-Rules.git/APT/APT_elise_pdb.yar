rule apt_elise_pdb {
	 
	 meta:

		 description = "Rule to detect Elise APT based on the PDB reference"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2017-05-31"
		 rule_version = "v1"
      	 malware_type = "backdoor"
         malware_family = "Backdoor:W32/Elise"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
         reference = "https://attack.mitre.org/software/S0081/"
		 hash = "b426dbe0f281fe44495c47b35c0fb61b28558b5c8d9418876e22ec3de4df9e7b"
	
	 strings:

		 $pdb = "\\lstudio\\projects\\lotus\\elise\\Release\\EliseDLL\\i386\\EliseDLL.pdb"
		 $pdb1 = "\\LStudio\\Projects\\Lotus\\Elise\\Release\\SetElise.pdb"
		 $pdb2 = "\\lstudio\\projects\\lotus\\elise\\Release\\SetElise\\i386\\SetElise.pdb"
		 $pdb3 = "\\LStudio\\Projects\\Lotus\\Elise\\Release\\Uninstaller.pdb"
		 $pdb4 = "\\lstudio\\projects\\lotus\\evora\\Release\\EvoraDLL\\i386\\EvoraDLL.pdb"

	 condition:

	  uint16(0) == 0x5a4d and 
      filesize < 50KB and 
      any of them
}
