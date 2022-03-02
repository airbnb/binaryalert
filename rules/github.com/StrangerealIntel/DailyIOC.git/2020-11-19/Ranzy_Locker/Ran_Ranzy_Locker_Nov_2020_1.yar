rule Ran_Ranzy_Locker_Nov_2020_1 {
   meta:
      description = " Detect Ranzy Locker (RAAS)"
      reference = "https://labs.sentinelone.com/ranzy-ransomware-better-encryption-among-new-features-of-thunderx-derivative/"
      date = "2020-11-19"
      hash1 = "393fd0768b24cd76ca653af3eba9bff93c6740a2669b30cf59f8a064c46437a2"
      hash2 = "90691a36d1556ba7a77d0216f730d6cd9a9063e71626489094313c0afe85a939"
      hash3 = "ade5d0fe2679fb8af652e14c40e099e0c1aaea950c25165cebb1550e33579a79"
      hash4 = "bbf122cce1176b041648c4e772b230ec49ed11396270f54ad2c5956113caf7b7"
      hash5 = "c4f72b292750e9332b1f1b9761d5aefc07301bc15edf31adeaf2e608000ec1c9"
   strings:
      $s1 = "776261646D696E2044454C4554452053595354454D53544154454241434B5550" ascii // 'wmic.exe SHADOWCOPY /nointeractive'
      $s2 = "776D69632E65786520534841444F57434F5059202F6E6F696E746572616374697665" ascii // 'SOFTWARE\Microsoft\ERID'
      $s3 = "76737361646D696E2E6578652044656C65746520536861646F7773202F416C6C202F5175696574" ascii // 'vssadmin.exe Delete Shadows /All /Quiet' 
      $s4 = "776261646D696E2044454C4554452053595354454D53544154454241434B5550202D64656C6574654F6C64657374" ascii // 'wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest'
      $s5 = "534F4654574152455C4D6963726F736F66745C45524944" ascii // 'SOFTWARE\Microsoft\ERID'
      $s6 = "626364656469742E657865202F736574207B64656661756C747D20626F6F74737461747573706F6C6963792069676E6F7265616C6C6661696C75726573" // 'bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures'
      $s7 = "7B5549447D" ascii // '{UID}'
      $s8 = "7B5041545445524E5F49447D" ascii // '{PATTERN_ID}' 
      $s9 = "726561646D652E747874" ascii // 'readme.txt'
      $s10 = "226E6574776F726B223A22" ascii // '"network":"'
      $s11 = "226C616E67223A22" ascii // '"lang":"'
      $s12 = "7B4558547D" ascii // '{EXT}'
      $s13 = "476C6F62616C5C33353335354641352D303745392D343238422D423541352D314338384341423242343838" // 'Global\35355FA5-07E9-428B-B5A5-1C88CAB2B488'
      $s14 = "433A5C50726F6772616D2046696C65735C4D6963726F736F66742053514C20536572766572" ascii // 'C:\Program Files\Microsoft SQL Server'
      $s15 = "433A5C50726F6772616D2046696C65732028783836295C4D6963726F736F66742053514C20536572766572" ascii // 'C:\Program Files (x86)\Microsoft SQL Server' 
      $s16 = "227375626964223A22" ascii // '"subid":"'
      $s17 = "22657874223A22" ascii // '"ext":"'
      $s18 = "226B6579223A22" ascii // '"key":"'
      // seq encrypt
      $seq1 = { 8b 46 50 8d 4d a4 83 7d d4 10 53 8b 1d 14 80 41 00 89 45 a4 8d 45 c0 0f 43 45 c0 51 50 6a 00 6a 01 6a 00 ff 35 e8 1c 42 00 ff d3 85 c0 0f 84 b9 00 00 00 8b 46 68 8d 4d a4 83 7d ec 10 57 89 45 a4 8d 45 d8 0f 43 45 d8 33 ff 51 50 6a 00 47 57 6a 00 ff 35 e8 1c 42 00 ff d3 85 c0 0f 84 8a 00 00 00 c6 45 fc 02 33 db 8b 45 e8 8b 4d d0 03 c1 6a 0f 5a 89 5d b8 89 55 bc 88 5d a8 89 7d a4 3b c2 76 15 88 5d a0 8d 4d a8 ff 75 a0 50 e8 78 02 00 00 8b 4d d0 89 5d b8 83 7d d4 10 8d 45 c0 51 0f 43 45 c0 8d 4d a8 50 e8 ca de ff ff 83 7d ec 10 8d 45 d8 ff 75 e8 0f 43 45 d8 8d 4d a8 50 e8 b3 de ff ff 8d 45 a8 50 8d 4e 70 e8 b8 d8 ff ff 8d 4d a8 e8 3f bf ff ff 8d 4d d8 e8 37 bf ff ff 8d 4d c0 e8 2f bf ff ff b0 01 eb 12 8d 4d d8 e8 23 bf ff ff 8d 4d c0 e8 1b bf ff ff 32 c0 e8 3f f1 }
      //seq recon
      $seq2 = { 8b 75 08 33 ff 8b 55 0c 33 c0 89 b5 68 fb ff ff 89 bd ac fb ff ff c7 85 b0 fb ff ff 07 00 00 00 66 89 85 9c fb ff ff 89 7d fc 39 7a 10 0f 84 da 00 00 00 6a 02 0f 57 c0 8d 8d 84 fb ff ff 58 66 0f 13 85 bc fb ff ff 66 89 85 b4 fb ff ff e8 6e ac ff ff 83 78 14 10 72 02 8b 00 50 ff 15 18 82 41 00 8d 8d 84 fb ff ff 89 85 b8 fb ff ff e8 8f a8 ff ff 68 87 69 00 00 ff 15 0c 82 41 00 bb 01 04 00 00 66 89 85 b6 fb ff ff 53 8d 85 c4 fb ff ff 57 50 e8 fd 2d 00 00 83 c4 0c 8d 7d cc 33 c0 6a 08 59 6a 08 6a 20 f3 ab 8d 45 cc 50 53 8d 85 c4 fb ff ff 50 6a 10 8d 85 b4 fb ff ff 50 ff 15 1c 82 41 00 85 c0 75 45 8d 85 c4 fb ff ff 50 8d 8d 6c fb ff ff e8 7f a8 ff ff 8b d0 c6 45 fc 01 8d 8d 84 fb ff ff e8 26 ab ff ff 50 8d 8d 9c fb ff ff e8 88 bf ff ff 8d 8d 84 fb ff ff e8 c8 c2 ff ff 8d 8d 6c fb ff ff e8 f5 a7 ff ff 8d 85 9c fb }
   condition:
      uint16(0) == 0x5a4d and filesize > 80KB and 10 of ($s*) and 1 of ($seq*) 
}
