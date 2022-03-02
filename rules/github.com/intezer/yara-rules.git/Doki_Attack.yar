rule Doki_Attack
{
	meta:
		copyright = "Intezer Labs"
		author = "Intezer Labs"
		reference = "https://www.intezer.com"
        
    strings:
    
        $a1 = /curl --retry 3 -m 60 -o \/tmp\w{6}\/tmp\/tmp.{37}.*\\{3}\"http:\/{2}.*\.ngrok\.io[\s\S]*\\{3}\";/ nocase
        $a2 = /rm -rf \/tmp\w{6}\/etc\/crontab;/ nocase
        $s1 = /echo \\{3}\"(\*\s){4}\* root sh \/tmp\/tmp.*\\{3}\" \\{2}u003e\/tmp\w{6}\/etc\/cron.d\/1m;/ nocase
        $s2 = /echo \\{3}\"(\*\s){4}\* root sh \/tmp\/tmp\w*\\{3}\" \\{2}u003e\/tmp\w{6}\/etc\/crontab;/ nocase
        $s3 = /chroot \/tmp\w{6} sh -c \\{3}\"cron \|\| crond/ nocase
    condition:
       all of them
}
