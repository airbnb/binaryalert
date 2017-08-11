rule ransomware_windows_petya_variant_2
{
    meta:
        description = "Petya Ransomware new variant June 2017 using ETERNALBLUE"
        reference = "https://gist.github.com/vulnersCom/65fe44d27d29d7a5de4c176baba45759"
        author = "@fusionrace"
        md5 = "71b6a493388e7d0b40c83ce903bc6b04"
    strings:
        // psexec disguised - applicable to s1
        $s1 = "dllhost.dat" fullword wide
        $s2 = "\\\\%ws\\admin$\\%ws" fullword wide
        $s3 = "%s /node:\"%ws\" /user:\"%ws\" /password:\"%ws\"" fullword wide
        $s4 = "\\\\.\\PhysicalDrive" fullword wide
        $s5 =  ".3ds.7z.accdb.ai.asp.aspx.avhd.back.bak.c.cfg.conf.cpp.cs.ctl.dbf.disk.djvu.doc.docx.dwg.eml.fdb.gz.h.hdd.kdbx.mail.mdb.msg.nrg.ora.ost.ova.ovf.pdf.php.pmf.ppt.pptx.pst.pvi.py.pyc.rar.rtf.sln.sql.tar.vbox.vbs.vcb.vdi.vfd.vmc.vmdk.vmsd.vmx.vsdx.vsv.work.xls.xlsx.xvd.zip." fullword wide
    condition:
        3 of them
}
