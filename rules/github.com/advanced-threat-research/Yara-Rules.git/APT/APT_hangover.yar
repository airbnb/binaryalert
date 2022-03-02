rule apt_hanover_pdb
{
	 meta:

		 description = "Rule to detect hanover samples based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2012-01-05"
		 rule_version = "v1"
      	 malware_type = "backdoor"
         malware_family = "Backdoor:W32/Hanover"
      	 actor_type = "Cybercrime"
      	 actor_group = "Unknown"
		 reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		 hash = "a2460412575cdc187dfb69eb2847c5b43156af7f7d94b71422e7f771e8adb51e"
		 

 	strings:

		$pdb = "\\andrew\\Key\\Release\\Keylogger_32.pdb"
		$pdb1 = "\\BACK_UP_RELEASE_28_1_13\\General\\KG\\Release\\winsvcr.pdb"
		$pdb2 = "\\BackUP-Important\\PacketCapAndUpload_Backup\\voipsvcr\\Release\\voipsvcr.pdb"
		$pdb3 = "\\BNaga\\kaam\\New_FTP_2\\Release\\ftpback.pdb"
		$pdb4 = "\\DD0\\DD\\u\\Release\\dataup.pdb"
		$pdb5 = "\\Documents and Settings\\Admin\\Desktop\\Newuploader\\Release\\Newuploader.pdb"
		$pdb6 = "\\Documents and Settings\\Admin\\Desktop\\Uploader Code\\Release\\Newuploader.pdb"
		$pdb7 = "\\Documents and Settings\\Administrator\\Desktop\\nn\\Release\\nn.pdb"
		$pdb8 = "\\smse\\Debug\\smse.pdb"
		$pdb9 = "\\Users\\admin\\Documents\\Visual Studio 2008\\Projects\\DNLDR-no-ip\\Release\\DNLDR.pdb"
		$pdb10 = "\\final exe\\check\\Release\\check.pdb"
		$pdb11 = "\\Projects\\Elance\\AppInSecurityGroup\\FtpBackup\\Release\\Backup.pdb"
		$pdb12 = "\\projects\\windows\\MailPasswordDecryptor\\Release\\MailPasswordDecryptor.pdb"
		$pdb13 = "\\final project backup\\UPLODER FTP BASED\\New folder\\Tron 1.2.1(Ftp n Startup)\\Release\\Http_t.pdb"

 	condition:

 	uint16(0) == 0x5a4d and
 	filesize < 1000KB and
 	any of them
}

rule apt_hanover_appinbot_pdb
{
	 meta:

		 description = "Rule to detect hanover appinbot samples based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2012-01-05"
		 rule_version = "v1"
      	 malware_type = "backdoor"
         malware_family = "Backdoor:W32/Hanover"
      	 actor_type = "Cybercrime"
      	 actor_group = "Unknown"
		 reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		 hash = "6ad56d64444fa76e1ad43a8c260c493b9086d4116eb18af630e65d3fd39bf6d6"

	 strings:

		 $pdb = "\\BNaga\\backup_28_09_2010\\threads tut\\pen-backup\\BB_FUD_23\\Copy of client\\Copy of client\\appinbot_1.2_120308\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb1 = "\\BNaga\\SCode\\BOT\\MATRIX_1.2.2.0\\appinbot_1.2_120308\\Build\\Win32\\Release\\deleter.pdb"
		 $pdb2 = "\\Documents and Settings\\Admin\\Desktop\\appinbot_1.2_120308\\appinclient\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb3 = "\\Documents and Settings\\Administrator\\Desktop\\Backup\\17_8_2011\\MATRIX_1.3.4\\ CLIENT\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb4 = "\\Documents and Settings\\Administrator\\Desktop\\Backup\\17_8_2011\\MATRIX_1.3.4\\ MATRIX_1.3.4\\CLIENT\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb5 = "\\Documents and Settings\\Administrator\\Desktop\\Backup\\17_8_2011\\MATRIX_1.3.4\\MATRIX_1.3.4\\ CLIENT\\Build\\Win32\\Release\\deleter.pdb"
		 $pdb6 = "\\pen-backup\\Copy of client\\Copy of client\\appinbot_1.2_120308\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb7 = "\\pen-backup\\Copy of client\\Copy of client\\appinbot_1.2_120308\\Build\\Win32\\Release\\deleter.pdb"
		 $pdb8 = "\\temp\\elance\\PROTOCOL_1.2\\Build\\Win32\\Release\\deleter.pdb"
		 $pdb9 = "\\Users\\PRED@TOR\\Desktop\\appinbot_1.2_120308\\Build\\Win32\\Release\\deleter.pdb"
		 $pdb10 = "\\Users\\PRED@TOR\\Desktop\\MODIFIED PROJECT LAB\\admin\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb11 = "\\Desktop backup\\Copy\\appinbot_1.2_120308\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb12 = "\\Datahelp\\SCode\\BOT\\MATRIX_1.3.3\\CLIENT\\Build\\Win32\\Release\\appinclient.pdb"
 	
 	condition:

		uint16(0) == 0x5a4d and
	 	filesize < 440KB and
	 	any of them
}

rule apt_hanover_foler_pdb
{
	 meta:

		 description = "Rule to detect hanover foler samples"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2012-01-05"
		 rule_version = "v1"
      	 malware_type = "backdoor"
         malware_family = "Backdoor:W32/Hanover"
      	 actor_type = "Cybercrime"
      	 actor_group = "Unknown"
		 reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		 hash = "bd77d7f8af8329dfb0bcc0624d6d824d427fbaf859ab2dedd8629aa2f3b7ae0d"

	 strings:

		 $pdb = "\\Documents and Settings\\Administrator\\Desktop\\nn\\Release\\nn.pdb"
		 $pdb1 = "\\Documents and Settings\\Administrator\\Desktop\\UsbP\\Release\\UsbP.pdb"
		 $pdb2 = "\\Documents and Settings\\Administrator\\Desktop\\UsbP\\UsbP - u\\Release\\UsbP.pdb"
		 $pdb3 = "\\Monthly Task\\August 2011\\USB Prop\\Usb Propagator.09-24\\nn\\Release\\nn.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 480KB and
	 	any of them
}

rule apt_hanover_linog_pdb
{
	 meta:
		 description = "Rule to detect hanover linog samples based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2012-01-05"
		 rule_version = "v1"
      	 malware_type = "backdoor"
         malware_family = "Backdoor:W32/Hanover"
      	 actor_type = "Cybercrime"
      	 actor_group = "Unknown"
		 reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		 hash = "f6319fd0e1d3b9d3694c46f80208e70b389e7dcc6aaad2508b80575c604c5dba"

	 strings:

		 $pdb = "\\Users\\hp\\Desktop\\download\\Release\\download.pdb"
		 $pdb1 = "\\Backup-HP-ABCD-PC\\download\\Release\\download.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 165KB and
	 	any of them
}

rule apt_hanover_ron_babylon_pdb
{
	 meta:
		 
		 description = "apt_hanover_ron_babylon"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2012-01-05"
		 rule_version = "v1"
      	 malware_type = "backdoor"
         malware_family = "Backdoor:W32/Hanover"
      	 actor_type = "Cybercrime"
      	 actor_group = "Unknown"
		 reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		 hash = "784cfb1bfdd7080c658fad08b1f679bbb0c94e6e468a3605ea47cdce533df815"
  
 strings:

		 $pdb = "\\Users\\hp\\Desktop\\download\\Release\\download.pdb"
		 $pdb1 = "\\26_10_2010\\demoMusic\\Release\\demoMusic.pdb"
		 $pdb2 = "\\26_10_2010\\New_FTP_HttpWithLatestfile2\\Release\\httpbackup.pdb"
		 $pdb3 = "\\26_10_2010\\New_FTP_HttpWithLatestfile2_FirstBlood_Released\\ New_FTP_HttpWithLatestfile2\\Release\\FirstBloodA1.pdb"
		 $pdb4 = "\\app\\Http_t\\Release\\Crveter.pdb"
		 $pdb5 = "\\BNaga\\kaam\\Appin SOFWARES\\RON 2.0.0\\Release\\Ron.pdb"
		 $pdb6 = "\\BNaga\\kaam\\kaam\\NEW SOFWARES\\firstblood\\Release\\FirstBloodA1.pdb"
		 $pdb7 = "\\BNaga\\kaam\\kaam\\New_FTP_HttpWithLatestfile2_FirstBlood_Released\\ New_FTP_HttpWithLatestfile2\\Release\\Ron.pdb"
		 $pdb8 = "\\BNaga\\kaam\\New_FTP_HttpWithLatestfile2_FirstBlood_Released\\ New_FTP_HttpWithLatestfile2\\Release\\FirstBloodA1.pdb"
		 $pdb9 = "\\BNaga\\My Office kaam\\Appin SOFWARES\\HTTP\\RON 2.0.0\\Release\\Ron.pdb"
		 $pdb10 = "\\Documents and Settings\\abc\\Desktop\\Dragonball 1.0.2(WITHOUT DOWNLOAD LINK)\\Release\\Ron.pdb"
		 $pdb11 = "\\Documents and Settings\\Administrator\\Desktop\\Feb 2012\\kmail(httpform1.1) 02.09\\Release\\kmail.pdb"
		 $pdb12 = "\\MNaga\\My Office kaam\\Appin SOFWARES\\HTTP\\RON 2.0.0\\Release\\Ron.pdb"
		 $pdb13 = "\\N\\kl\\Release\\winlsa.pdb"
		 $pdb14 = "\\N\\sr\\Release\\waulct.pdb"
		 $pdb15 = "\\Release\\wauclt.pdb"
		 $pdb16 = "\\Users\\neeru rana\\Desktop\\Klogger- 30 may\\Klogger- 30 may\\Release\\Klogger.pdb"
		 $pdb17 = "\\december task backup\\TRINITY PAYLOAD\\Dragonball 1.0.0(WITHOUT DOWNLOAD LINK)\\Release\\Ron.pdb"
		 $pdb18 = "\\Documents and Settings\\appin\\Desktop\\New_FTP_1\\New_FTP_1\\Release\\HTTP_MyService.pdb"
		 $pdb19 = "\\May Payload\\new keylogger\\Flashdance1.0.2\\kmail(http) 01.20\\Release\\kmail.pdb"
		 $pdb20 = "\\Monthly Task\\September 2011\\HangOver 1.3.2 (Startup)\\Release\\Http_t.pdb"
		 $pdb21 = "\\Sept 2012\\Keylogger\\Release\\Crveter.pdb"
		 $pdb22 = "\\Datahelp\\keytest1\\keytest\\taskmng.pdb"
		 $pdb23 = "\\Datahelp\\UPLO\\HTTP\\HTTP_T\\17_05_2011\\Release\\Http_t.pdb"
		 $pdb24 = "\\Datahelp\\UPLO\\HTTP\\HTTP_T\\20_05_2011\\Release\\Http_t.pdb"
		 $pdb25 = "\\June mac paylods\\final Klogger-1 june-Fud from eset5.0\\Klogger- 30 may\\Klogger- 30 may\\Release\\Klogger.pdb"
		 $pdb26 = "\\June mac paylods\\Keylo ger backup\\final Klogger-1 june-Fud from eset5.0\\Klogger- 30 may\\Klogger- 30 may\\Release\\kquant.pdb"
		 $pdb27 = "\\June mac paylods\\Keylogger backup\\final Klogger-1 june-Fud from eset5.0\\Klogger- 30 may\\Klogger- 30 may\\Release\\kquant.pdb"
		 $pdb28 = "\\My\\lan scanner\\Task\\HangOver 1.2.2\\Release\\Http_t.pdb"
		 $pdb29 = "\\New folder\\paylod backup\\OTHER\\Uploder\\HangOver 1.5.7 (Startup)\\HangOver 1.5.7 (Startup)\\Release\\Http_t.pdb"
		 $pdb30 = "\\keyloger\\KeyLog\\keytest1\\keytest\\taskmng.pdb"
		 $pdb31 = "\\august\\13 aug\\HangOver 1.5.7 (Startup) uploader\\Release\\Http_t.pdb"
		 $pdb32 = "\\backup E\\SourceCodeBackup\\september\\aradhana\\HangOver 1.5.3 (Startup)\\Release\\Http_t.pdb"
		 $pdb33 = "\\payloads\\new backup feb\\SUNDAY\\kmail(http) 01.20\\kmail(http) 01.20\\Release\\kmail.pdb"
		 $pdb34 = "\\payloads\\ita nagar\\Uploader\\HangOver 1.5.7 (Startup)\\HangOver 1.5.7 (Startup)\\Release\\Http_t.pdb"
		 $pdb35 = "\\final project backup\\task information\\task of september\\Tourist 2.4.3 (Down Link On Resource) -L\\Release\\Ron.pdb"
		 $pdb36 = "\\final project backup\\complete task of ad downloader & usb grabber&uploader\\New folder\\with icon +shortcut link\\HangOver 1.5.3 (Startup)\\Release\\Http_t.pdb"
		 $pdb37 = "\\final project backup\\uploader version backup\\fud all av hangover1.5.4\\with icon +shortcut link\\HangOver 1.5.3 (Startup)\\Release\\Http_t.pdb"
		 $pdb38 = "\\final project backup\\uploader version backup\\HangOver 1.5.3 (Startup)\\Release\\Http_t.pdb"
		 $pdb39 = "\\New folder\\with icon +shortcut link\\HangOver 1.5.3 (Startup)\\Release\\Http_t.pdb"
		 $pdb40 = "\\Http uploader limited account\\Http uploader limited account\\RON 2.0.0\\Release\\Ron.pdb"
		 $pdb41 = "\\Uploader\\HTTP\\HTTP Babylon 5.1.1\\HTTP Babylon 5.1.1\\Httpbackup\\Release\\HttpUploader.pdb"
		 $pdb42 = "\\Uploader\\HTTP\\ron uplo\\RON 2.0.0\\Release\\Ron.pdb"

 	condition:

 		uint16(0) == 0x5a4d and
	 	filesize < 330KB and
	 	any of them
}

rule apt_hanover_slidewin_pdb
{
	 meta:

		 description = "Rule to detect hanover slidewin samples"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2012-01-05"
		 rule_version = "v1"
      	 malware_type = "backdoor"
         malware_family = "Backdoor:W32/Hanover"
      	 actor_type = "Cybercrime"
      	 actor_group = "Unknown"
		 reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		 hash = "89b80267f9c7fc291474e5751c2e42838fdab7a5cbd50a322ed8f8efc3d2ce83"

	 strings:

		 $pdb = "\\Users\\God\\Desktop\\ThreadScheduler-aapnews-Catroot2\\Release\\ThreadScheduler.pdb"
		 $pdb1 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-hostzi\\Release\\slidebar.pdb"
		 $pdb2 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-spectram\\Release\\slidebar.pdb"
		 $pdb3 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-zendossier\\Release\\slidebar.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 100KB and
	 	any of them
}
