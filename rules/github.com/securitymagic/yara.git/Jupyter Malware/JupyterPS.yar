/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
rule Jupyter_Infostealer_DLL
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed powershell command strings"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $a = /\[.\..\]::run\(\)/ nocase
      $b = /\[.\..\]::run\(\)/ nocase wide
  condition:
      any of them
}
