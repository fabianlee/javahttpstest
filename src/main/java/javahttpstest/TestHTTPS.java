package javahttpstest;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;

// used for AnyCertTrustManager, but that is commented out
//import java.security.cert.CertificateException;
//import javax.net.ssl.X509TrustManager;


public class TestHTTPS {
	
	private static String DEFAULT_URL = "https://www.google.com";

	protected static String JAVA_KEYSTORE_ALGORITHM = "JKS";
	protected static String JAVA_TRUST_ALGORITHM = "PKIX";
	protected static String DEFAULT_TLS_PROTOCOL = "TLSv1.2";
	static {
		// Java 1.7 does not support TLSv1.2
		if("1.7".equals(System.getProperty("java.version").substring(0, 2))) {
			DEFAULT_TLS_PROTOCOL = "TLSv1";
		}
	}
	
	// there are three ways the trust manager can be specified
	// the first two ways are part of the standard JVM implementation
	//
	// 1. JVM do nothing default: JVM pulls from $JAVA_HOME/jre/lib/security/cacerts, jssecacerts
	// 2. System property: file path set in standard property 'javax.net.ssl.trustStore' tells JVM which keystore file to use
	// 3. Classpath: looks for a keystore in classpath based on system property 'classpath.trustStore', useful for jar
	protected boolean isTrustManagerDefault = true;
	protected boolean isTrustManagerSpecifiedByFilePath = false;
	protected boolean isTrustManagerSpecifiedByClasspath = false;
	
	// default password for JRE store, and we will assume any custom keystores
	char[] trustedStorePassword = "changeit".toCharArray();
	
	
	
	public static void main(String args[]) throws Exception {
		TestHTTPS mytest = new TestHTTPS();
		mytest.run();
	}
	
	public void run() throws Exception {
		
		init();
		
		// setup standard or custom SSLContext based on System properties
		SSLContext context = configureSSLContext();
		
		// create socket based on context
        SSLSocketFactory factory = (SSLSocketFactory)context.getSocketFactory();
        SSLSocket socket = (SSLSocket)factory.createSocket();
        
        // show JVM supported protocols/ciphers independent of site being pulled
        printAvailableSSLProtocols(socket);
        
        // create connection based on parameters set in context
		URL url = new URL(DEFAULT_URL);
		HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
		connection.setSSLSocketFactory(context.getSocketFactory());
		
		// show remote certificate information
		printHTTPSCerts(connection);

		// get content from remote host
		printURLContent(connection);

		
	}

	public void init() throws Exception {
		
		File currentDirectory = new File(new File(".").getAbsolutePath());
		System.out.println("Current Directory: " + currentDirectory.getCanonicalPath());
		
		System.out.println("java.version = " + System.getProperty("java.version"));
		System.out.println("DEFAULT_PROTOCOL: " + DEFAULT_TLS_PROTOCOL);
		
		if(null!=System.getProperty("javax.net.ssl.trustStore")) {
			System.out.println("javax.net.ssl.trustStore: " + System.getProperty("javax.net.ssl.trustStore"));
			System.out.println("javax.net.ssl.trustStorePassword: " + System.getProperty("javax.net.ssl.trustStorePassword"));
			
			isTrustManagerDefault = false;
			isTrustManagerSpecifiedByFilePath = true;	
			System.out.println("Trust keystore: user specified from System properties: " + System.getProperty("javax.net.ssl.trustStore"));
			
		}else if(null!=System.getProperty("classpath.trustStore")) {
			System.out.println("classpath.trustStore: " + System.getProperty("classpath.trustStore"));
			System.out.println("classpath.trustStorePassword: " + System.getProperty("classpath.trustStorePassword"));
			if(null!=System.getProperty("classpath.trustStorePassword")) {
				trustedStorePassword = System.getProperty("classpath.trustStorePassword").toCharArray();
			}
			
			isTrustManagerDefault = false;
			isTrustManagerSpecifiedByClasspath = true;
			System.out.println("Trust keystore: user specified from classpath: " + System.getProperty("classpath.trustStore"));
			
		}else {
			System.out.println("Trust keystore: JVM default");
		}
		

		// override default URL if user specified
		if (null != System.getProperty("URL")) {
			DEFAULT_URL = System.getProperty("URL");
			System.out.println("Overrode URL: " + DEFAULT_URL);
		} else {
			System.out.println("Default URL: " + DEFAULT_URL);
		}
		
		
	}
	
	public SSLContext configureSSLContext() throws Exception {
		
		SSLContext context = null;
		
		if(isTrustManagerDefault) {
			
			System.out.println("Setting up SSLContext using default JVM implementation with no overrides");
			context = SSLContext.getInstance(DEFAULT_TLS_PROTOCOL);
			context.init(null, null, null);
			
		}else if(isTrustManagerSpecifiedByFilePath) {
			
			System.out.println("Setting up SSLContext using standard JVM override with system property 'javax.net.ssl.trustStore'");
			context = SSLContext.getInstance(DEFAULT_TLS_PROTOCOL);
			context.init(null, null, null);
			
		}else if(isTrustManagerSpecifiedByClasspath) {
			
			System.out.println("Setting up SSLContext with classpath location specified by use in system property 'classpath.trustStore'");
			String classpathLocation = System.getProperty("classpath.trustStore");
			InputStream jksIS = getClass().getResourceAsStream(classpathLocation);
			if(jksIS==null) {
				throw new Exception("could not find " + classpathLocation + " in root classpath");	
			}

			// show default and used algorithms for key and trust manager
			System.out.println("KeyManager default algo: " + KeyManagerFactory.getDefaultAlgorithm() + " ;using: " + JAVA_KEYSTORE_ALGORITHM);
			System.out.println("TrustManager default algo: " + TrustManagerFactory.getDefaultAlgorithm() + " ;using: " + JAVA_TRUST_ALGORITHM);

			// load trust keystore from classpath
	        KeyStore ks = KeyStore.getInstance(JAVA_KEYSTORE_ALGORITHM);
			try {
				ks.load(jksIS, trustedStorePassword);
				
				// keyStore.aliases() is Enumeration, convert to Iterable so we can use it in 'for'
				System.out.println("\r\nAliases found in " + classpathLocation + ":");
				for(String alias:Collections.list(ks.aliases())) {
					System.out.println("\talias: " + alias);
				}
				System.out.println();
				
			} finally {
				jksIS.close();
			}
	        
	        // create trust manager
	        TrustManagerFactory tmFactory = TrustManagerFactory.getInstance(JAVA_TRUST_ALGORITHM);
	        tmFactory.init(ks);
	        TrustManager[] tm = tmFactory.getTrustManagers();
	        
	        // initialize context, do not use getDefault() because that is immutable
			context = SSLContext.getInstance(DEFAULT_TLS_PROTOCOL);
			// only override trust manager, 2nd parameter
			// nulls means not to override (key manager and secure random)
			context.init(null, tm, null);
			
		}
		
		return context;
	}

	
	// https://gist.github.com/lanimall/cb7d84c8d6c6301d4d0c
	private void printAvailableSSLProtocols(SSLSocket socket) throws Exception {
		
		System.out.println("\r\n\r\n----------JVM SUPPORTED CIPHERS/PROTOCOLS--------------");
        String[] protocols = socket.getSupportedProtocols();

        System.out.println("Supported Protocols: " + protocols.length);
        for(int i = 0; i < protocols.length; i++)
        {
            System.out.println(" " + protocols[i]);
        }

        protocols = socket.getEnabledProtocols();

        System.out.println("Enabled Protocols: " + protocols.length);
        for(int i = 0; i < protocols.length; i++)
        {
            System.out.println(" " + protocols[i]);
        }


        String[] ciphers = socket.getSupportedCipherSuites();
        System.out.println("Enabled Ciphers: " + ciphers.length);
        for(int i = 0; i < ciphers.length; i++)
        {
            //System.out.println(" " + ciphers[i]);
        }
		
	}
	
	// https://www.mkyong.com/java/java-https-client-httpsurlconnection-example/
	private void printHTTPSCerts(HttpsURLConnection con) {

		System.out.println("\r\n\r\n----------REMOTE CERTS--------------");
		if (con != null) {

			try {

				System.out.println("Response Code : " + con.getResponseCode());
				System.out.println("Cipher Suite : " + con.getCipherSuite());
				System.out.println("\n");

				SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
				Certificate[] certs = con.getServerCertificates();
				for (Certificate cert : certs) {
					System.out.println("Cert Type : " + cert.getType());
					System.out.println("Cert Hash Code : " + cert.hashCode());
					System.out.println("Cert Public Key Algorithm : " + cert.getPublicKey().getAlgorithm());
					System.out.println("Cert Public Key Format : " + cert.getPublicKey().getFormat());
					if("X.509".equalsIgnoreCase(cert.getType())) {
						X509Certificate xcert = (X509Certificate)cert;
						System.out.println("Issuer: "  + xcert.getIssuerDN());
						System.out.println("Subject: " + xcert.getSubjectDN());
						System.out.println("Not Before: " + sdf.format(xcert.getNotBefore()));
						List<String> anames = getSubjectAlternativeNames(xcert);
						for(String name:anames) {
							System.out.println("SAN: " + name);
						}
						System.out.println("usage: " + CertificateInfo.getKeyUsageAsText(xcert));
						System.out.println("ext usage: " + CertificateInfo.getExtendedKeyUsageAsText(xcert));
						System.out.println("\n");
						
						
					} // if x509
					
				} // each cert

			} catch (SSLPeerUnverifiedException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			} 

		}

	}

	// https://www.mkyong.com/java/java-https-client-httpsurlconnection-example/
	private void printURLContent(HttpsURLConnection con) {
		System.out.println("\r\n\r\n----------REMOTE CONTENT--------------");
		if (con != null) {

			try {

				BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));

				StringBuffer sbuf = new StringBuffer(1024);
				String input;

				while ((input = br.readLine()) != null) {
					sbuf.append(input);
				}
				br.close();
				
				System.out.println("Full length of content received: " +sbuf.length());
				if(sbuf.length()>1024) {
					System.out.println("Truncating length of content to 1024 so that output is not cluttered");
					System.out.println(sbuf.substring(0, 512));
						System.out.println("....truncated....");
					System.out.println(sbuf.substring(sbuf.length()-513));
				}else {
					System.out.println(sbuf);
				}

			} catch (IOException e) {
				e.printStackTrace();
			}

		}

	}
	
	public static List<String> getSubjectAlternativeNames(X509Certificate certificate) {
        List<String> identities = new ArrayList<String>();
        try {
            Collection<List<?>> altNames = certificate.getSubjectAlternativeNames();
            if (altNames == null)
                return Collections.emptyList();
            for (List item : altNames) {
                Integer type = (Integer) item.get(0);
                if (type == 0 || type == 2){
                    try {
                        ASN1InputStream decoder=null;
                        if(item.toArray()[1] instanceof byte[])
                            decoder = new ASN1InputStream((byte[]) item.toArray()[1]);
                        else if(item.toArray()[1] instanceof String)
                            identities.add( (String) item.toArray()[1] );
                        if(decoder==null) continue;
                        
                        // modified for newest bouncycastle
                        ASN1Primitive encoded = decoder.readObject();
                        String identity = encoded.toString();
                        System.out.println(identity);
                        identities.add(identity);
                        
                        
/* ORIGINAL CODE, but only works with <1.46 versions of bouncycastle
                        DEREncodable encoded = decoder.readObject();
                        encoded = ((DERSequence) encoded).getObjectAt(1);
                        encoded = ((DERTaggedObject) encoded).getObject();
                        encoded = ((DERTaggedObject) encoded).getObject();
                        String identity = ((DERUTF8String) encoded).getString();
                        identities.add(identity);
*/                        
                    }
                    catch (UnsupportedEncodingException e) {
                        System.err.println("Error decoding subjectAltName" + e.getLocalizedMessage());
                    }
                    catch (Exception e) {
                    	System.err.println("Error decoding subjectAltName" + e.getLocalizedMessage());
                    }
                }else{
                	System.err.println("SubjectAltName of invalid type found: " + certificate);
                }
            }
        }
        catch (CertificateParsingException e) {
        	System.err.println("Error parsing SubjectAltName in certificate: " + certificate + "\r\nerror:" + e.getLocalizedMessage());
        }
        return identities;
    }
	
	
	// https://wiki.apache.org/thrift/Thrift%20%26%20Eclipse%20%26%20JUnit%20with%20TServlet
	/* UNUSED - often used as a trust manager implementation when using self-signed certs to avoid errors
	 * but this is a workaround, what really should be done is that the self-signed cert is added to the truststore
	private static class AnyCertTrustManager implements X509TrustManager {
		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		}
		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		}
		@Override
		public X509Certificate[] getAcceptedIssuers() {
			// for any cert
			return null;
		}
	}
	*/	

	
	

}
