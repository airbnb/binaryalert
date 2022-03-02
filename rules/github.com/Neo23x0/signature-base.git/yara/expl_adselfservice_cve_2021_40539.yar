
rule LOG_EXPL_ADSelfService_CVE_2021_40539_ADSLOG_Sep21 : LOG {
   meta:
      description = "Detects suspicious log lines produeced during the exploitation of ADSelfService vulnerability CVE-2021-40539"
      author = "Florian Roth"
      reference = "https://us-cert.cisa.gov/ncas/alerts/aa21-259a"
      date = "2021-09-20"
      score = 70
   strings:
      $x1 = "Java traceback errors that include references to NullPointerException in addSmartCardConfig or getSmartCardConfig" ascii wide
   condition:
      filesize < 50MB and 1 of them
}

rule LOG_EXPL_ADSelfService_CVE_2021_40539_WebLog_Sep21_1 : LOG {
   meta:
      description = "Detects suspicious log lines produeced during the exploitation of ADSelfService vulnerability CVE-2021-40539"
      author = "Florian Roth"
      reference = "https://us-cert.cisa.gov/ncas/alerts/aa21-259a"
      date = "2021-09-20"
      score = 60
   strings:
      $x1 = "/ServletApi/../RestApi/LogonCustomization" ascii wide
      $x2 = "/ServletApi/../RestAPI/Connection" ascii wide
   condition:
      filesize < 50MB and 1 of them
}
