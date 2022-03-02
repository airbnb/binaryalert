rule anatova_ransomware {

   meta:

      description = "Rule to detect the Anatova Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-01-22"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Anatova"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/happy-new-year-2019-anatova-is-here/"
      hash = "97fb79ca6fc5d24384bf5ae3d01bf5e77f1d2c0716968681e79c097a7d95fb93"

   strings:

      $regex = /anatova[0-9]@tutanota.com/
        
    condition:

        uint16(0) == 0x5a4d and
        filesize < 2000KB and
        $regex
}
