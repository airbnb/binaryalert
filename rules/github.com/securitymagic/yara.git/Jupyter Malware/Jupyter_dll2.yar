/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
rule Jupyter_Infostealer_DLL_October2021
{
  meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed wide strings with malicious DLL loaded by Jupyer malware"
        reference = "https://squiblydoo.blog/2021/10/17/solarmarker-by-any-other-name/" 
  strings:
      $reggie = /[0-9a-fA-F]{32}\.dll/ wide
      $web = /https?:/ nocase wide
      $path = "appdata" nocase wide
      $rsa = "RSAKeyValue" wide
      $packer = "dzkabr"
      $ps = "System.IO.File" wide
  condition:
      ($reggie and $web and $path) and ($rsa or $packer or $ps)
}
