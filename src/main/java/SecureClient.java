package org.eclipse.californium.examples;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.logging.Level;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.coap.MediaTypeRegistry;




public class SecureClient {
	
	static {
		ScandiumLogger.initialize();
		ScandiumLogger.setLevel(Level.FINE);
	}


	private static final String TRUST_STORE_PASSWORD = "rootPass";
	private final static String KEY_STORE_PASSWORD = "endPass";
	private static final String KEY_STORE_LOCATION = "keyStore.jks";
	private static final String TRUST_STORE_LOCATION = "trustStore.jks";

	private DTLSConnector dtlsConnector;

	public SecureClient() {
		try {
			// load key store
			KeyStore keyStore = KeyStore.getInstance("JKS");
			InputStream in = getClass().getClassLoader().getResourceAsStream(KEY_STORE_LOCATION);
			keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());

			// load trust store
			KeyStore trustStore = KeyStore.getInstance("JKS");
			InputStream inTrust = getClass().getClassLoader().getResourceAsStream(TRUST_STORE_LOCATION);
			trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());

			// You can load multiple certificates if needed
			Certificate[] trustedCertificates = new Certificate[1];
			trustedCertificates[0] = trustStore.getCertificate("root");

			DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(0));
			builder.setPskStore(new StaticPskStore("Client_identity", "secretPSK".getBytes()));
			builder.setIdentity((PrivateKey)keyStore.getKey("client", KEY_STORE_PASSWORD.toCharArray()),
					keyStore.getCertificateChain("client"), true);
			builder.setTrustStore(trustedCertificates);
			dtlsConnector = new DTLSConnector(builder.build());

		} catch (GeneralSecurityException | IOException e) {
			System.err.println("Could not load the keystore");
			e.printStackTrace();
		}
	}

	public void test() {
				
		URI uri = null;
		
		String u = "coaps://localhost/secure";
		
		try {
			uri = new URI(u);
		} catch (URISyntaxException e) {
			System.err.println("Invalid URI: " + e.getMessage());
			System.exit(-1);
		}

		CoapClient client = new CoapClient(uri);
		client.setEndpoint(new CoapEndpoint(dtlsConnector, NetworkConfig.getStandard()));

		for(int i = 0; i<99; i++){
			client.post(new CoapHandler() {
				public void onLoad(CoapResponse response) {
					System.out.println(Utils.prettyPrint(response));
					System.out.println(new String(response.getPayload()));
				}

				@Override
				public void onError() {
					System.out.println("error push");
				}
			}, ("test"+i).getBytes(), MediaTypeRegistry.TEXT_PLAIN);

		}
		try {
			dtlsConnector.start();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) throws InterruptedException {

		SecureClient client = new SecureClient();
		client.test();

		synchronized (SecureClient.class) {
			SecureClient.class.wait();
		}
	}

}
