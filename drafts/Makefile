all: cookie.xml
	../tools/xml2rfc-1.35pre1/xml2rfc.tcl cookie.xml
	java -classpath ../tools/saxonhe9-2-0-5j/saxon9he.jar net.sf.saxon.Transform -novw -l cookie.xml ../tools/rfc2629xslt/extract-artwork.xslt type="abnf2616" > syntax.abnf
	../tools/bap/bap syntax.abnf
