import "pe"
import "math"

include "hacktool_windows_cobaltstrike_template.yara"

rule hacktool_windows_cobaltstrike_artifact_exe
{
    meta:
        description = "Detection of the Artifact payload from Cobalt Strike"
        reference = "https://www.cobaltstrike.com/help-artifact-kit"
        author = "@javutin, @joseselvi"
    condition:
        cobaltstrike_template_exe and
        filesize < 100KB and
        pe.sections[pe.section_index(".data")].raw_data_size > 512 and
        math.entropy(pe.sections[pe.section_index(".data")].raw_data_offset, 512 ) >= 7
}