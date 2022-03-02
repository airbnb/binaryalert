rule APT_APT_C_23_Micropsia_Mar_2021_1 {
   meta:
        description = "Detect Micropsia used by APT-C-23 (Build 2018)"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-03-31"
        hash1 = "eb846bb491bea698b99eab80d58fd1f2530b0c1ee5588f7ea02ce0ce209ddb60"
        level = "experimental"
   strings:
        // code reuse
        $code1 = { c7 85 6c fc ff ff 12 00 00 00 8b f4 8d 85 6c fc ff ff 50 8d 8d 78 fc ff ff 51 ff 15 44 b0 66 00 3b f4 e8 80 d6 fa ff 8d 85 78 fc ff ff 50 b9 e0 83 66 00 e8 06 0d fb ff 6a 00 e8 24 0a 00 00 83 c4 04 50 e8 a2 d9 fa ff 83 c4 04 c7 85 60 fc ff ff }
        $code2 = { 68 34 4f 61 00 8d 85 cc fd ff ff 50 e8 3d 02 fd ff 83 c4 08 8b f4 6a 00 6a 00 6a 00 6a 00 8d 85 e8 fd ff ff 50 ff 15 60 b3 66 00 3b f4 e8 f2 0d fd ff 89 85 c0 fd ff ff 83 bd c0 fd ff ff 00 0f 84 49 03 00 00 8b f4 6a 00 6a 00 6a 03 6a 00 6a 00 0f b7 05 d4 83 66 00 50 8b 4d 10 51 8b 95 c0 fd ff ff 52 ff 15 58 b3 66 00 3b f4 e8 b3 0d fd ff 89 85 b4 fd ff ff 83 bd b4 fd ff ff 00 0f 84 f4 02 00 00 8b f4 6a 00 a1 d8 83 66 00 50 6a 00 6a 00 68 5c 4f 61 00 8b 4d 14 51 8d 95 cc fd ff ff 52 8b 85 b4 fd ff ff 50 ff 15 70 b3 66 00 3b f4 e8 6e 0d fd ff 89 85 a8 fd ff ff 83 bd a8 fd ff ff 00 0f 84 af 02 00 00 c7 85 9c fd ff ff 00 00 00 00 83 }
        $code3 = { 8b 85 60 fc ff ff 83 c0 01 89 85 60 fc ff ff 83 bd 60 fc ff ff 0a 7d 2a e8 3f fc fa ff 99 b9 1a 00 00 00 f7 f9 83 c2 41 88 95 57 fc ff ff 0f b6 85 57 fc ff ff 50 b9 e0 83 66 00 e8 8b 14 fb }
        $s1 = "szhttpUserAgent" fullword ascii 
        $s2 = "httpUseragent" fullword ascii 
        $s3 = "dwByteRead" fullword ascii 
        $s4 = { 25 59 25 6d 25 64 2d 25 49 2d 25 4d 2d 25 53 } // %Y%m%d-%I-%M-%S
        $s5 = { 53 45 4c 45 43 54 20 27 43 52 45 41 54 45 20 49 4e 44 45 58 20 76 61 63 75 75 6d 5f 64 62 2e 27 20 7c 7c 20 73 75 62 73 74 72 28 73 71 6c 2c 31 34 29 20 20 46 52 4f 4d 20 73 71 6c 69 74 65 5f 6d 61 73 74 65 72 20 57 48 45 52 45 20 73 71 6c 20 4c 49 4b 45 20 27 43 52 45 41 54 45 20 49 4e 44 45 58 20 25 27 } // SELECT 'CREATE INDEX vacuum_db.' || substr(sql,14)  FROM sqlite_master WHERE sql LIKE 'CREATE INDEX %' 
        $s6 = { 55 50 44 41 54 45 20 25 51 2e 25 73 20 53 45 54 20 73 71 6c 20 3d 20 43 41 53 45 20 57 48 45 4e 20 74 79 70 65 20 3d 20 27 74 72 69 67 67 65 72 27 20 54 48 45 4e 20 73 71 6c 69 74 65 5f 72 65 6e 61 6d 65 5f 74 72 69 67 67 65 72 28 73 71 6c 2c 20 25 51 29 45 4c 53 45 20 73 71 6c 69 74 65 5f 72 65 6e 61 6d 65 5f 74 61 62 6c 65 28 73 71 6c 2c 20 25 51 29 20 45 4e 44 2c 20 74 62 6c 5f 6e 61 6d 65 20 3d 20 25 51 2c 20 6e 61 6d 65 20 3d 20 43 41 53 45 20 57 48 45 4e 20 74 79 70 65 3d 27 74 61 62 6c 65 27 20 54 48 45 4e 20 25 51 20 57 48 45 4e 20 6e 61 6d 65 20 4c 49 4b 45 20 27 73 71 6c 69 74 65 5f 61 75 74 6f 69 6e 64 65 78 25 25 27 20 41 4e 44 20 74 79 70 65 3d 27 69 6e 64 65 78 27 20 54 48 45 4e 20 27 73 71 6c 69 74 65 5f 61 75 74 6f 69 6e 64 65 78 5f 27 20 7c 7c 20 25 51 20 7c 7c 20 73 75 62 73 74 72 28 6e 61 6d 65 2c 25 64 2b 31 38 29 20 45 4c 53 45 20 6e 61 6d 65 20 45 4e 44 20 57 48 45 52 45 20 74 62 6c 5f 6e 61 6d 65 3d 25 51 20 43 4f 4c 4c 41 54 45 20 6e 6f 63 61 73 65 20 41 4e 44 20 28 74 79 70 65 3d 27 74 61 62 6c 65 27 20 4f 52 20 74 79 70 65 3d 27 69 6e 64 65 78 27 20 4f 52 20 74 79 70 65 3d 27 74 72 69 67 67 65 72 27 29 3b } // UPDATE %Q.%s SET sql = CASE WHEN type = 'trigger' THEN sqlite_rename_trigger(sql, %Q)ELSE sqlite_rename_table(sql, %Q) END, tbl_name = %Q, name = CASE WHEN type='table' THEN %Q WHEN name LIKE 'sqlite_autoindex%%' AND type='index' THEN 'sqlite_autoindex_' || %Q || substr(name,%d+18) ELSE name END WHERE tbl_name=%Q COLLATE nocase AND (type='table' OR type='index' OR type='trigger');
        $s7 = { 25 00 6c 00 73 00 28 00 25 00 64 00 29 } // %ls(%d) : %ls
        $s8 = { 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 25 73 0d 0a } // Content-Type: %s\r\n
   condition:
        uint16(0) == 0x5a4d and filesize > 50KB and 2 of ($code*) and 5 of ($s*)
}
