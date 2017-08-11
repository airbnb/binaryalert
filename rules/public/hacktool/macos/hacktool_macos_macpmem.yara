include "../../MachO.yara"

rule hacktool_macos_macpmem
{
    meta:
        description = "MacPmem enables read/write access to physical memory on macOS. Can be used by CSIRT teams and attackers."
        reference = "https://github.com/google/rekall/tree/master/tools/osx/MacPmem"
        author = "@mimeframe"
    strings:
        // osxpmem
        $a1 = "%s/MacPmem.kext" wide ascii
        $a2 = "The Pmem physical memory imager." wide ascii
        $a3 = "The OSXPmem memory imager." wide ascii
        $a4 = "These AFF4 Volumes will be loaded and their metadata will be parsed before the program runs." wide ascii
        $a5 = "Pmem driver version incompatible. Reported" wide ascii
        $a6 = "Memory access driver left loaded since you specified the -l flag." wide ascii
        // kext
        $b1 = "Unloading MacPmem" wide ascii
        $b2 = "MacPmem load tag is" wide ascii
    condition:
        MachO and 2 of ($a*) or all of ($b*)
}
