
rule Ransom_Win_BlackCat
{
  meta:
  description = "Detecting variants of Windows BlackCat malware"
  author = " Trellix ATR"
  date = "2022-01-06"
  malware_type = "Ransomware"
  detection_name = "Ransom_Win_BlackCat"
  actor_group = "Unknown"

strings:

 $URL1 = "zujgzbu5y64xbmvc42addp4lxkoosb4tslf5mehnh7pvqjpwxn5gokyd.onion" ascii wide
 $URL2 = "mu75ltv3lxd24dbyu6gtvmnwybecigs5auki7fces437xvvflzva2nqd.onion" ascii wide

 $API = { 3a 7c d8 3f }

 condition:
  uint16(0) == 0x5a4d and
  filesize < 3500KB and
  1 of ($URL*) and
  $API
}
