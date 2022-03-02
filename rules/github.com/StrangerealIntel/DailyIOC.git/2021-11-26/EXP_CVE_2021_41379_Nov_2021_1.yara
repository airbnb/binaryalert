rule EXP_CVE_2021_41379_Nov_2021_1
{
    meta:
        description = "Detect exploit tool using CVE-2021-41379"
        author = "Arkbird_SOLG"
        date = "2021-11-26"
        reference = "https://twitter.com/JAMESWT_MHT/status/1463414554004709384"
        hash1 = "5d97d3035b2ec1bd16016922899350693cae5f7a3be6cadbe0da34fbfd14b612"
        hash2 = "76fe99189fa84e28dd346b1105da77c4dfd3f7f16478b05bfca4c13a75d9fd07"
	hash3 = "9e4763ddb6ac4377217c382cf6e61221efca0b0254074a3746ee03d3d421dabd"
	hash4 = "a018545b334dc2a0e0c437789a339c608852fa1cedcc88be9713806b0855faea"
        tlp = "white"
        adversary = "-"
    strings:
        $s1 = { 50 6a 01 50 68 03 00 08 00 68 [3] 00 ff 15 [3] 00 8b f0 83 fe ff 0f 84 [2] 00 00 6a 00 56 ff 15 88 [2] 00 8d 85 ?? fb ff ff c7 85 ?? fb ff ff 00 00 00 00 50 56 ff 15 [3] 00 8b 3d [3] 00 56 ff d7 ff 15 [3] 00 50 6a 00 68 00 10 10 00 ff 15 [3] 00 8b f0 c7 85 ?? fb ff ff 00 00 00 00 8d 85 ?? fb ff ff 50 68 ff 01 0f 00 56 ff 15 [3] 00 56 ff d7 8d 85 ?? fb ff ff c7 85 ?? fb ff ff 00 00 00 00 50 6a 01 6a 02 6a 00 68 ff 01 0f 00 ff b5 ?? fb ff ff ff 15 [3] 00 ff b5 ?? fb ff ff ff d7 6a 04 8d 85 ?? fb ff ff 50 6a 0c ff b5 ?? fb ff ff ff 15 08 [2] 00 6a 44 8d 85 78 fb ff ff 0f 57 c0 6a 00 50 0f 11 85 bc fb ff ff e8 [2] 00 00 83 c4 0c c7 85 78 fb ff ff 44 00 00 00 b8 05 00 00 00 c7 85 80 fb ff ff [3] 00 66 89 85 a8 fb ff ff 8d 85 e8 fd ff ff 68 04 01 00 00 50 68 [3] 00 ff 15 [3] 00 8d 85 bc fb ff ff 50 8d 85 78 fb ff ff 50 6a 00 6a 00 6a 10 6a 00 6a 00 6a 00 6a 00 8d 85 e8 fd ff ff 50 ff b5 ?? fb ff ff ff 15 [3] 00 ff b5 ?? fb ff ff ff d7 ff b5 bc fb ff ff ff d7 ff b5 c0 fb ff ff ff d7 }
	$s2 = { 6a 00 68 80 00 00 04 6a 04 6a 00 6a 01 68 00 00 01 80 8d 85 e8 fd ff ff 50 ff 15 [3] 00 8b 35 [3] 00 a3 [3] 00 8d 85 d8 fb ff ff 50 6a 00 6a 00 68 [2] 40 00 6a 00 6a 00 c7 85 d8 fb ff ff 00 00 00 00 ff d6 8b f8 8b 85 dc fb ff ff 68 [3] 00 05 0c 02 00 00 68 04 01 00 00 50 } 
	$s3 = { 55 8b ec 81 ec 04 08 00 00 a1 04 [2] 00 33 c5 89 45 fc 0f 10 05 [3] 00 ?? 8b ?? 08 8d 85 2c f8 ff ff [0-1] 0f 11 85 fc f7 ff ff [1-5] 0f 10 05 [3] 00 [3-8] 0f 11 85 0c f8 ff ff [0-1] 0f 10 05 }
	$s4 = { 50 ff ?? 68 04 01 00 00 8d 85 e0 fb ff ff 50 6a 00 ff 15 [3] 00 50 ff 15 [3] 00 6a 00 e8 [2] ff ff 50 8d 85 e0 fb ff ff 50 ff 15 84 [2] 00 6a 00 ff 15 [3] 00 8d 85 ?? fb ff ff 50 68 [3] 00 6a 04 6a 00 68 [3] 00 ff 15 [3] 00 ff 15 [3] 00 8b 35 [3] 00 8b 3d [3] 00 } 
    condition:
       uint16(0) == 0x5A4D and filesize > 25KB and all of ($s*)
}  
