import "hash"
import "pe"

rule Rclone
{
    meta:
        id = "23v8f9e4P2BkrMqYH5mcBN"
        fingerprint = "4f7ec548a91c112a2d05f3b8449f934e2e4eaf7bf6dab032a26ac3511799a7bf"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Rclone, sometimes used by attackers to exfiltrate data."
        category = "MALWARE"
        malware_type = "INFOSTEALER"
        reference = "https://rclone.org/"


    strings:
        $ = "github.com/rclone/" ascii wide
        $ = "The Rclone Authors" ascii wide
        $ = "It copies the drive file with ID given to the path" ascii wide
        $ = "rc vfs/forget file=hello file2=goodbye dir=home/junk" ascii wide
        $ = "rc to flush the whole directory cache" ascii wide

    condition:
        any of them or for any i in (0..pe.number_of_resources-1) : (pe.resources[i].type==pe.RESOURCE_TYPE_ICON and hash.md5(pe.resources[i].offset,pe.resources[i].length)=="fc675e36c61c8b9d0b956bd05695cdda")
}