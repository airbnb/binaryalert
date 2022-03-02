rule rietspoof_loader {
   
   meta:
      
      description = "Rule to detect the Rietspoof loader"
      author = "Marc Rivero | McAfee ATR Team"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Loader:W32/Rietspoof"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://blog.avast.com/rietspoof-malware-increases-activity"
      
   strings:

      $x1 = "\\Work\\d2Od7s43\\techloader\\loader" fullword ascii
    
   condition:

      uint16(0) == 0x5a4d and
      all of them
}
