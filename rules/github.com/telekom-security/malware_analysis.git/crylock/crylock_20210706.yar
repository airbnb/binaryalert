rule Crylock_binary {
   meta:
      description = "Detects CryLock ransomware v2.3.0.0"
      author = "Thomas Barabosch, Telekom Security"
      reference = "TBA"
      date = "2021-06-28"
   strings:
      $s1 = "how_to_decrypt.hta" ascii
      $s2 = "UAC annoy and ask admin rights" ascii
      $s3 = "<%UNDECRYPT_DATETIME%>" ascii
      $s4 = "<%RESERVE_CONTACT%>" ascii
      $s5 = "<%MAIN_CONTACT%>" ascii
      $s6 = "<%HID%>" ascii
      $s7 = "Get local IPs list" ascii
      $s8 = "Get password hash" ascii
      $s9 = "END PROCESSES KILL LIST" ascii
      $s10 = "CIS zone detected" ascii
      $s11 = "Launch encryption threads..." ascii
      $s12 = "FastBlackRabbit" ascii
      $s13 = "Preliminary password hash calculation" ascii
      $s14 = "Encrypted:" ascii
   condition:
      uint16(0) == 0x5a4d
      and filesize > 150KB
      and filesize < 1MB
      and 8 of ($s*)
}

rule Crylock_hta {
   meta:
      description = "Detects CryLock ransomware how_to_decrypt.hta ransom note"
      author = "Thomas Barabosch, Telekom Security"
      reference = "TBA"
      date = "2021-06-28"
   strings:
      $s1 = "var main_contact =" ascii
      $s2 = "var max_discount =" ascii
      $s3 = "<title>CryLock</title>" ascii
      $s4 = "var discount_date = new Date(" ascii
      $s5 = "var main_contact =" ascii
      $s6 = "var hid = " ascii
      $s7 = "var second_contact = " ascii
      $s8 = "document.getElementById('main_contact').innerHTML = main_contact;" ascii
      $s9 = "document.getElementById('second_contact').innerHTML = second_contact;" ascii
      $s10 = "document.getElementById('hid').innerHTML = hid;" ascii
      $s11 = "be able to decrypt your files. Contact us" ascii
      $s12 = "Attention! This important information for you" ascii
      $s13 = "higher will become the decryption key price" ascii
      $s14 = "Before payment, we can decrypt three files for free." ascii
   condition:
      filesize < 100KB
      and 8 of ($s*)
}
