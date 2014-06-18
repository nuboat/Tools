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

import static org.testng.Assert.*;
import org.testng.annotations.Test;

/**
 *
 * @author nuboat
 */
public class InstallCertNGTest {

	@Test
	public void testMain() throws Exception {
		final String source = "./src/main/resources/cacerts";
		final char[] passphrase = "changeit".toCharArray();
		final String host = "tableau.entiera.com";
		final int port = 443;
		final String output = "./src/main/resources/jssecacerts";
		final char[] outputpassphase = "changeit".toCharArray();
		
		InstallCert.add(source, passphrase, host, port, output, outputpassphase);
	}

	@Test
	public void testToHexString() throws Exception {
		final String hex = "11";
		final String expected = "31 31 ";
		
		final String actual = InstallCert.toHexString(hex.getBytes());
		
		assertEquals(actual, expected);
	}
	
}
