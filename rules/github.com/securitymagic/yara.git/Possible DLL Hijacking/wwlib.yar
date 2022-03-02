/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
rule possible_wwlib_hijacking
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed with campaigns such as APT32, this attempts to look for the archive files such as RAR."
        reference = "040abac56542a2e0f384adf37c8f95b2b6e6ce3a0ff969e3c1d572e6b4053ff3" 
    strings:
        $a = "\\wwlib.dll"
        $neg = "This program cannot be run in DOS mode"
    condition:
        $a and not $neg
}
