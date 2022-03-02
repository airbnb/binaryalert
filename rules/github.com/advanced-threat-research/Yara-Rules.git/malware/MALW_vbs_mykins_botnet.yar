rule vbs_mykins_botnet {

   meta:

      description = "Rule to detect the VBS files used in Mykins botnet"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2018-01-24"
      rule_version = "v1"
      malware_type = "botnet"
      malware_family = "Botnet:W32/MyKins"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://blog.netlab.360.com/mykings-the-botnet-behind-multiple-active-spreading-botnets/"
      
   strings:

      $s1 = "fso.DeleteFile(WScript.ScriptFullName)" fullword ascii
      $s2 = "Set ws = CreateObject(\"Wscript.Shell\")" fullword ascii
      $s3 = "Set fso = CreateObject(\"Scripting.Filesystemobject\")" fullword ascii
      $r = /Windows\\ime|web|inf|\\c[0-9].bat/

   condition:

      uint16(0) == 0x6553 and
      filesize < 1KB 
      and any of ($s*) and
      $r  
      
}
