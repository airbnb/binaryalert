rule QnapCrypt
{	
	meta:
		copyright = "Intezer Labs"
		author = "Intezer Labs"
		reference = "https://www.intezer.com"
	
    strings:
        $a = "Do NOT remove this file and NOT remove last line in this file!" nocase
        $b0 = "main.writemessage"
        $b1 = "inf.1st.3ds.3fr.4db.4dd.602.a4p.a5w.abf.abw.act.adr.aep.aes.aex.aim.alx.ans.apk.apt.arj.aro.arw.asa.asc.ase.asp.asr.att.aty.avi.awm.awp.awt.aww.axd.bar.bat.bay.bc6.bc7.big.bik.bin.bit.bkf.bkp.bml.bok.bpw.bsa.bwp.bz2.c++.cab.cas.cat.cdf.cdr.cer.cfg.cfm.cfr.cha.chm.cms.con.cpg.cpp.cr2.crl.crp.crt.crw.csp.csr.css.csv.cxx.dap.das.dat.db0.dba.dbf.dbm.dbx.dcr.der.dll.dml.dmp.dng.doc.dot.dwg.dwk.dwt.dxf.dxg.ece.eml.epk.eps.erf.esm.ewp.far.fdb.fit.flv.fmp.fos.fpk.fsh.fwp.gdb.gho.gif.gne.gpg.gsp.gxk.hdm.hkx.htc.htm.htx.hxs.idc.idx.ifx.iqy.iso.itl.itm.iwd.iwi.jcz.jpe.jpg.jsp.jss.jst.jvs.jws.kdb.kdc.key.kit.ksd.lbc.lbf.lrf.ltx.lvl.lzh.m3u.m4a.map.max.mdb.mdf.mef.mht.mjs.mlx.mov.moz.mp3.mpd.mpp.mvc.mvr.myo.nba.nbf.ncf.ngc.nod.nrw.nsf.ntl.nv2.nxg.nzb.oam.odb.odc.odm.odp.ods.odt.ofx.olp.orf.oth.p12.p7b.p7c.pac.pak.pdb.pdd.pdf.pef.pem.pfx.pgp.php.png.pot.ppj.pps.ppt.prf.pro.psd.psk.psp.pst.psw.ptw.ptx.pub.qba.qbb.qbo.qbw.qbx.qdf.qfx.qic.qif.qrm.r3d.raf.rar.raw.re4.rim.rjs.rsn.rss.rtf.rw2.rw3.rwl.rwp.saj.sav.sdb.sdc.sdf.sht.sid.sie.sis.sko.slm.snx.spc.sql.sr2.src.srf.srw.ssp.stc.stl.stm.stp.sum.svc.svg.svr.swz.sxc.t12.t13.tar.tax.tbl.tbz.tcl.tgz.tib.tor.tpl.txt.ucf.upk.url.vbd.vbo.vcf.vdf.vdi.vdw.vlp.vmx.vpk.vrt.vtf.w3x.wav.wb2.wbs.wdb.web.wgp.wgt.wma.wml.wmo.wmv.woa.wpd.wpp.wps.wpx.wrf.x3f.x_t.xbl.xbm.xht.xla.xlk.xll.xlm.xls.xlt.xlw.xml.xpd.xpm.xps.xss.xul.xwd.xws.xxx.zfo.zip.zul.zvz"
        $b2 = "main.makesecret"
        $b3 = "main.chDir"
        $b4 = "main.writemessage"
        $b5 = "main.randSeq"
        $b6 = "main.encrypt"
    condition:
        $a or 2 of ($b*)
}
