import "pe"

rule megacortex_signed {

    meta:

        description = "Rule to detect MegaCortex samples digitally signed"
        author = "Marc Rivero | McAfee ATR Team"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/MegaCortex"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://blog.malwarebytes.com/detections/ransom-megacortex/"
        
    condition:

      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].subject contains "/C=GB/L=ROMFORD/O=3AN LIMITED/CN=3AN LIMITED"  and
         pe.signatures[i].serial == "04:c7:cd:cc:16:98:e2:5b:49:3e:b4:33:8d:5e:2f:8b" or
         pe.signatures[i].subject contains "/C=GB/postalCode=RM6 4DE/ST=ROMFORD/L=ROMFORD/street=8 Quarles Park Road/O=3AN LIMITED/CN=3AN LIMITED"  and
         pe.signatures[i].serial == "53:cc:4c:69:e5:6a:7d:bc:36:67:d5:ff:d5:24:aa:4b" or
         pe.signatures[i].subject contains "/C=GB/postalCode=RM6 4DE/ST=ROMFORD/L=ROMFORD/street=8 Quarles Park Road/O=3AN LIMITED/CN=3AN LIMITED" or
         pe.signatures[i].serial == "00:ad:72:9a:65:f1:78:47:ac:b8:f8:49:6a:76:80:ff:1e")
}
