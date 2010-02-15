all: cookie.xml
	../tools/xml2rfc-1.35pre1/xml2rfc.tcl cookie.xml
	java -classpath ../tools/saxonhe9-2-0-5j/saxon9he.jar net.sf.saxon.Transform -novw -l cookie.xml ../tools/rfc2629xslt/extract-artwork.xslt type="abnf" > syntax.abnf
	echo >> syntax.abnf # Add a newline at EOF to make bap happy.
	../tools/bap/bap syntax.abnf
