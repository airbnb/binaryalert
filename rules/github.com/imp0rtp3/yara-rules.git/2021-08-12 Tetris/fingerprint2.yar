rule SUSP_JSframework_fingerprint2
{
	meta:
		author      = "@imp0rtp3"
		description = "fingerprint2 JS library signature, can be used for legitimate purposes"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"

	strings:

		$m1 = "valentin.vasilyev"
		$m2 = "Valentin Vasilyev"
		$m3 = "Fingerprintjs2"
		$a1 = "2277735313"
		$a2 = "289559509"
		$a3 = "1291169091"
		$a4 = "658871167"
		$a5 = "excludeIOS11"
		$a6 = "sortPluginsFor"
		$a7 = "Cwm fjordbank glyphs vext quiz, \\ud83d\\ude03"
		$a8 = "varyinTexCoordinate"
		$a9 = "webgl alpha bits:"
		$a10 = "WEBKIT_EXT_texture_filter_anisotropic"
		$a11 = "mmmmmmmmmmlli"
		$a12 = "'new Fingerprint()' is deprecated, see https://github.com/Valve/fingerprintjs2#upgrade-guide-from-182-to-200"
		$b1 = "AcroPDF.PDF"
		$b2 = "Adodb.Stream"
		$b3 = "AgControl.AgControl"
		$b4 = "DevalVRXCtrl.DevalVRXCtrl.1"
		$b5 = "MacromediaFlashPaper.MacromediaFlashPaper"
		$b6 = "Msxml2.DOMDocument"
		$b7 = "Msxml2.XMLHTTP"
		$b8 = "PDF.PdfCtrl"
		$b9 = "QuickTime.QuickTime"
		$b10 = "QuickTimeCheckObject.QuickTimeCheck.1"
		$b11 = "RealPlayer"
		$b12 = "RealPlayer.RealPlayer(tm) ActiveX Control (32-bit)"
		$b13 = "RealVideo.RealVideo(tm) ActiveX Control (32-bit)"
		$b14 = "Scripting.Dictionary"
		$b15 = "SWCtl.SWCtl"
		$b16 = "Shell.UIHelper"
		$b17 = "ShockwaveFlash.ShockwaveFlash"
		$b18 = "Skype.Detection"
		$b19 = "TDCCtl.TDCCtl"
		$b20 = "WMPlayer.OCX"
		$b21 = "rmocx.RealPlayer G2 Control"
		$b22 = "rmocx.RealPlayer G2 Control.1"

	condition:
		filesize < 1000000 and (
			(
				all of ($m*) and 
				2 of ($a*)
			) 
			or 8 of ($a*)
			or (
				5 of ($a*)
				and 13 of ($b*)
			)
		)

}


