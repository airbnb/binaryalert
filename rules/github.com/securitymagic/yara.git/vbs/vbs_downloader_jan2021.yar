/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
rule vbs_downloader_jan2021
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "VBS downloader campaign appearing January 2021"
	referencs = "http://security5magics.blogspot.com/2021/01/new-vbs-downloader-variant-observed.html"
  strings:
      $a = "vbSystemModal" nocase
      $b = "programdata" nocase
      $c = "regsvr32" nocase
      $d = "objStream.Open" nocase
      $e = "responseBody" nocase
      $f = "a.setOption 2,13056" nocase
  condition:
      ($a and $b and $c and $d and $e) or $f
}
