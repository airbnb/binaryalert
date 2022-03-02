rule apt_CN_Tetris_JS_simple
{

	meta:
		author      = "@imp0rtp3"
		description = "Jetriz, Swid & Jeniva from Tetris framework signature"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"
		
	strings:
		$a1 = "c2lnbmFs" // 'noRefererJsonp'
		$a2 = "ZW50cmllcw==" // 'BIDUBrowser'
		$a3 = "aGVhcnRCZWF0cw==" // 'Int8Array,Uint8Array,Uint8ClampedArray,Int16Array,Uint16Array,Int32Array,Uint32Array,Float32Array,Float64Array'
		$a4 = "ZmV0Y2g=" // 'return new F('
		$a5 = "c3BsaWNl" // 'Mb2345Browser'
		$a6 = "TWl1aUJyb3dzZXI=" // 'ipec'
		$a7 = "Zm9udA==" // 'heartBeats'
		$a8 = "OS4w" // 'addIEMeta'
		$a9 = "Xi4qS29ucXVlcm9yXC8oW1xkLl0rKS4qJA==" // 'ClientRectList'
		$a10 = "dHJpbVJpZ2h0" // '<script>document.F=Object</script>'
		$a11 = "UHJlc3Rv" // 'baiduboxapp'
		$a12 = "Xi4qUWlob29Ccm93c2VyXC8oW1xkLl0rKS4qJA==" // 'OnlineTimer'
		$a13 = "bWFyaw==" // 'regeneratorRuntime = r'
		$a14 = "cHJvamVjdElk" // 'onrejectionhandled'
		$a15 = "IHJlcXVpcmVkIQ==" // 'finallyLoc'

		$b1 = "var a0_0x"

	condition:
		$b1 at 0 or
		5 of ($a*)

}

