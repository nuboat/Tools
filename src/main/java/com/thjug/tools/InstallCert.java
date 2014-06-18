/**
 * <pre>
 * Attribution
 * CC BY
 * This license lets others distribute, remix, tweak,
 * and build upon your work, even commercially,
 * as long as they credit you for the original creation.
 * This is the most accommodating of licenses offered.
 * Recommended for maximum dissemination and use of licensed materials.
 *
 * http://creativecommons.org/licenses/by/3.0/
 * http://creativecommons.org/licenses/by/3.0/legalcode
 * </pre>
 */
package com.thjug.tools;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Default cert path : $JAVA_HOME\jre\lib\security
 * @author nuboat
 */
public class InstallCert {

    public static void main(final String[] args) {
		final String source = args[0];
		final char[] passphrase = args[1].toCharArray();
		final String host = args[2];
		final int port = Integer.parseInt(args[3]);
		final String output = args[4];
		final char[] outputpassphase = args[5].toCharArray();
		
		try {
			add(source, passphrase, host, port, output, outputpassphase);
		} catch (final Exception e) {
			e.printStackTrace();
		}
    }
	
	/**
	 * 
	 * @param source Path of cacerts file
	 * @param passphrase **password
	 * @param host Host url without :port
	 * @param port SSL port
	 * @param output Path of new cacerts file
	 * @param outputpassphase **password
	 * @return	true if certificate is already trusted.
	 *			false if certificate has added.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws CertificateEncodingException
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws KeyManagementException 
	 */
	public static void add(final String source, 
			final char[] passphrase, 
			final String host, 
			final int port, 
			final String output, 
			final char[] outputpassphase) 
			throws Exception {

		final KeyStore ks = loadKeyStore(source, passphrase);
		
		final X509Certificate[] chain = loadCertificate(ks, host, port);
		if (chain != null) {
			printCertificate(chain);

			int i = 1;
			try (final OutputStream out = new FileOutputStream(output)) {
				for (final X509Certificate cert : chain) {
					final String alias = host + "-" + i++;
					ks.setCertificateEntry(alias, cert);
					ks.store(out, outputpassphase);

					System.out.println();
					System.out.println(cert);
					System.out.println();
					System.out.println("Added certificate to keystore 'cacerts.jks' using alias '"  + alias + "'");
				}
			}
		}

	}

	public static void printCertificate(final X509Certificate[] chain) 
			throws NoSuchAlgorithmException, CertificateEncodingException {
		
		System.out.println();
		System.out.println("Server sent " + chain.length + " certificate(s):");
		System.out.println();
		
		final MessageDigest sha1 = MessageDigest.getInstance("SHA1");
		final MessageDigest md5 = MessageDigest.getInstance("MD5");
		for (final X509Certificate cert : chain) {
			System.out.println(" Subject " + cert.getSubjectDN());
			System.out.println("   Issuer  " + cert.getIssuerDN());
			sha1.update(cert.getEncoded());
			System.out.println("   sha1    " + toHexString(sha1.digest()));
			md5.update(cert.getEncoded());
			System.out.println("   md5     " + toHexString(md5.digest()));
		}
	}

	public static KeyStore loadKeyStore(final String source, final char[] passphrase) 
			throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
		final File file = new File(source);
		System.out.println("Loading KeyStore " + file + "...");

		final KeyStore ks;
		try (final InputStream in = new FileInputStream(file)) {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(in, passphrase);
		}
		return ks;
	}
	
	public static X509Certificate [] loadCertificate(final KeyStore ks, final String host, final int port) 
			throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		final SSLContext context = SSLContext.getInstance("TLS");
		final TrustManagerFactory tmf =
				TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(ks);
		final X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
		final SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
		context.init(null, new TrustManager[]{tm}, null);
		final SSLSocketFactory factory = context.getSocketFactory();
		System.out.println("Opening connection to " + host + ":" + port + "...");
		try (final SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
			socket.setSoTimeout(10000);
			System.out.println("Starting SSL handshake...");
			socket.startHandshake();
			System.out.println();
			System.out.println("No errors, certificate is already trusted");
			
			return null;
		} catch (final SSLHandshakeException e) {
			return tm.chain;
		}
	}

    private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

    public static String toHexString(final byte[] bytes) {
        final StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int b : bytes) {
            b &= 0xff;
            sb.append(HEXDIGITS[b >> 4]);
            sb.append(HEXDIGITS[b & 15]);
            sb.append(' ');
        }
        return sb.toString();
    }

    private static class SavingTrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        private X509Certificate[] chain;

        SavingTrustManager(final X509TrustManager tm) {
            this.tm = tm;
        }

		@Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

		@Override
        public void checkClientTrusted(final X509Certificate[] chain, final String authType)
                throws CertificateException {
            throw new UnsupportedOperationException();
        }

		@Override
        public void checkServerTrusted(final X509Certificate[] chain, final String authType)
                throws CertificateException {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }

}