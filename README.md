Tools
===================

InstallCert
-----
Install certificate into TrustStore by destination URL.
	"source, passphrase, host, port, output, outputpassphase"
	Load KeyStore from source file then test handshake with host:port
	if can't handshake add certificate and write a new file.

 1. args[0] = Source file
 -  args[1] = Passphrase of source file
 -  args[2] = host url
 -  args[3] = host port
 -  args[3] = Output file
 -  args[3] = Passphrase of output file
