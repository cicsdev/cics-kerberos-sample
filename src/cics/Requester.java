
/* Licensed Materials - Property of IBM                                   */
/*                                                                        */
/* SAMPLE                                                                 */
/*                                                                        */
/* (c) Copyright IBM Corp. 2018 All Rights Reserved                       */
/*                                                                        */
/* US Government Users Restricted Rights - Use, duplication or disclosure */
/* restricted by GSA ADP Schedule Contract with IBM Corp                  */
/*                                                                        */

package cics;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivilegedAction;
import java.util.HashMap;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.xml.bind.DatatypeConverter;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * Provides a simple test of a CICS Kerberos configuration using CICS web services.
 * The code uses standard Java APIs to request a Kerberos token from a KDC and 
 * passes that token on a 'hello world' web service request to a CICS server.
 * 
 * The web service client implementation is trivial and not intended to be a 
 * demonstration of how to use web services. The aim of this sample is to 
 * provide a simple test on a Kerberos configuration. 
 * 
 * Exceptions are not handled and instead are allowed to terminate the program so 
 * that the user can more easily see the error responses for an invalid configuration.
 *
 */
public class Requester {

	// suitable Kerberos defaults for this hello world test
	private static final boolean requestMutualAuth = false;
	private static final boolean requestCredDeleg = false;
	private static final boolean requestConf = false;

	/**
	 * Simple username/password login callback handler
	 */
	private static class LoginCallbackHandler implements CallbackHandler {
		private String password;
		private String username;

		public LoginCallbackHandler(String username, String password) {
			super();
			this.username = username;
			this.password = password;
		}

		@Override
		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

			for (Callback callback : callbacks) {
				if (callback instanceof NameCallback && username != null) {
					NameCallback nc = (NameCallback) callback;
					nc.setName(username);
				} else if (callback instanceof PasswordCallback) {
					PasswordCallback pc = (PasswordCallback) callback;
					pc.setPassword(password.toCharArray());
				} else {
					throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
				}
			}
		}
	}

	/**
	 * /** Trivial JAAS login configuration for Krb5
	 */
	private static class Krb5LoginConfiguration extends Configuration {
		private AppConfigurationEntry[] configs;

		/**
		 * Default constructor
		 */
		public Krb5LoginConfiguration() {

			HashMap<String, Object> options = new HashMap<String, Object>();
			options.put("refreshKrb5Config", "true");
			options.put("debug", "true");
			AppConfigurationEntry entry = new AppConfigurationEntry("com.ibm.security.auth.module.Krb5LoginModule",
					LoginModuleControlFlag.REQUIRED, options);
			configs = new AppConfigurationEntry[] { entry };
		}

		@Override
		public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
			return configs;
		}

	}

	public static void main(String[] args) throws LoginException, GSSException {
		String inputMsg1 = "<?xml version=\"1.0\"  standalone=\"no\"?> " + "<soapenv:Envelope "
				+ "xmlns:q0=\"http://www.ECHOPROG.ECHOCOMM.Request.com\" "
				+ "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"> "
				+ "<SOAP-ENV:Header xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"> "
				+ "<wsse:Security SOAP-ENV:mustUnderstand=\"0\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"> "
				+ "<wss:BinarySecurityToken EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#Kerberosv5_AP_REQ\" Id=\"uuide7eafbbf-0143-1ffd-8da2-b17ce09c1b4d\" xmlns:wss=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">";

		// kerberos token to be inserted here in message

		String inputMsg2 = "</wss:BinarySecurityToken> " + "</wsse:Security> " + "</SOAP-ENV:Header> "
				+ "<soapenv:Body> " + "<q0:ECHOPROGOperation> " + "<q0:echo_string> ";

		// echo string to be inserted here in message

		String inputMsg3 = "</q0:echo_string> " + "</q0:ECHOPROGOperation> " + "</soapenv:Body> "
				+ "</soapenv:Envelope>";

		System.out.println("Web service requester for CICS Echo service");
		System.out.println("-------------------------------------------");
		if (args.length != 7) {
			System.out.println("Usage: cics.Requester host:port echoString realm kdc clientPrincipalName clientPassword servicePrincipalName");
			return;
		}
		String hostAndPort 			= args[0];
		String EchoString 			= args[1];
		String realm 				= args[2];
		String kdc 					= args[3];
		String clientPrincipalName  = args[4]; 
		String clientPassword       = args[5]; 
		String servicePrincipalName = args[6];

		String destURL = "http://" + hostAndPort + "/ca1p/echoProgProviderBatch";
		
		System.out.println("Parameters");
		System.out.println("Host:Port = " 			 + hostAndPort);
		System.out.println("EchoString = " 			 + EchoString);
		System.out.println("realm =	"				 + realm);
		System.out.println("kdc = "					 + kdc);
		System.out.println("clientPrincipalName = "  + clientPrincipalName); 
		System.out.println("clientPassword = "       + clientPassword); 
		System.out.println("servicePrincipalName = " + servicePrincipalName);
		System.out.println("");
		System.out.println("Target URL is : " + destURL);
		System.out.println("");
		System.out.println("");

		// get a kerberos token
		String tokenString = getKerberosToken(
				realm,
				kdc,
				clientPrincipalName, 
				clientPassword, 
				servicePrincipalName);

		// build up the soap request
		StringBuffer fullmsgBuffer = new StringBuffer(inputMsg1);
		fullmsgBuffer.append(tokenString);
		fullmsgBuffer.append(inputMsg2);
		fullmsgBuffer.append(EchoString);
		fullmsgBuffer.append(inputMsg3);
		String fullmsg = fullmsgBuffer.toString();

		System.out.println("Request message");
		System.out.println("---------------");
		System.out.println("");
		System.out.println(fullmsg);
		try {
			HttpURLConnection httpConn = (HttpURLConnection) new URL(destURL).openConnection();

			byte[] b = fullmsg.getBytes("utf-8");

			httpConn.setRequestProperty("Content-Length", String.valueOf(b.length));
			httpConn.setRequestProperty("Content-Type", "text/xml; charset=utf-8");
			httpConn.setRequestProperty("Connection", "close");
			httpConn.setRequestProperty("SOAPAction", "\"\"");
			httpConn.setRequestMethod("POST");
			httpConn.setDoOutput(true);
			httpConn.setDoInput(true);

			OutputStream outputStream = httpConn.getOutputStream();
			outputStream.write(b);
			outputStream.close();

			System.out.println("");
			System.out.println("Attempting to read response");
			System.out.println("---------------------------");
			System.out.println("");
			DataInputStream inputStream = new DataInputStream(httpConn.getInputStream());
			try {
				StringBuffer sb = new StringBuffer(8096);
				int i;
				while ((i = inputStream.read()) != -1) {
					// int i;
					sb.append((char) i);
				}
				System.out.println(sb.toString());
				System.out.println("");
				System.out.println("End of response");
			} catch (EOFException e) {
				System.out.println("End of response");
			}
			inputStream.close();
			httpConn.disconnect();
		} catch (Exception e) {
			System.out.println("An exception occured");
			System.out.println("");
			e.printStackTrace();
			System.out.println("");
		}
	}

	private static String getKerberosToken(
			String realm,
			String kdc,
			String clientPrincipalName, 
			String clientPassword, 
			String servicePrincipalName) throws LoginException, GSSException {

		setSystemPropertiesForKerberos(realm, kdc);

		// create the GSS-API security context 
		GSSContext context = createSecurityContext(clientPrincipalName, clientPassword, servicePrincipalName);
		if (context != null) {
			System.out.println("Successfully created GSS-API security context");
			System.out.println(context);
			
			// get a kerberos token
			byte[] tokenBytes = initiateSecurityContext(context);

			String base64Token = base64EncodedBytes(tokenBytes);
			System.out.println("Successfully obtained a kerberos token:" + base64Token);
			return base64Token;
		}
		else {
			System.out.println("failed to get a kerberos token");
			return null;
		}
	}

	private static void setSystemPropertiesForKerberos(String realm, String kdc) {
		// setting the realm & KDC here is more flexible for testing than using a krb5 file
		System.setProperty("java.security.krb5.realm", realm);
		System.setProperty("java.security.krb5.kdc", kdc);
		System.setProperty("javax.security.auth.useSubjectCredsOnly", "true");
	}

	private static GSSContext createSecurityContext(final String clientPrincipalName, String clientPassword, final String servicePrincipalName) throws LoginException {
		// Create the JAAS login configuration
		Configuration config = new Krb5LoginConfiguration();

		// log into the KDC
		System.out.println("Attempting to log into the KDC");
		LoginContext lgnCtx;
		lgnCtx = new LoginContext("null", null, new LoginCallbackHandler(clientPrincipalName, clientPassword), config);
		lgnCtx.login();

		// Create the context from the subject
		GSSContext context = Subject.doAs(lgnCtx.getSubject(), new PrivilegedAction<GSSContext>() {
			public GSSContext run() {
				try {
					// OIDs for the Krb5 mechanism, and for the
					// principal name format
					Oid krb5MechOid = new Oid("1.2.840.113554.1.2.2");
					Oid krb5PrincNameOid = new Oid("1.2.840.113554.1.2.2.1");

					// Obtain the GSS manager
					GSSManager manager = GSSManager.getInstance();

					// Create the client credential
					GSSName clientName = manager.createName(clientPrincipalName, GSSName.NT_USER_NAME, krb5MechOid);
					GSSCredential clientCred = manager.createCredential(clientName, GSSCredential.DEFAULT_LIFETIME,
							krb5MechOid, GSSCredential.INITIATE_ONLY);

					// Create the server name
					GSSName serverName = manager.createName(servicePrincipalName, krb5PrincNameOid);

					// Create the context
					GSSContext context = manager.createContext(serverName, krb5MechOid, clientCred,
							GSSContext.DEFAULT_LIFETIME);

					// Set any requested properties
					context.requestMutualAuth(requestMutualAuth);
					context.requestCredDeleg(requestCredDeleg);
					context.requestConf(requestConf);

					return context;

				} catch (GSSException e) {
					// logger.error(
					// "There was an error attempting to create the security
					// context",
					// e);
					System.out.println("There was an error attempting to create the security context " + e);
					e.printStackTrace();
					return null;
				}
			}
		});
		return context;
	}

	private static byte[] initiateSecurityContext(GSSContext context) throws GSSException {
		byte[] inBytes = new byte[0];
		byte[] tokenBytes;
		tokenBytes = context.initSecContext(inBytes, 0, inBytes.length);
		return tokenBytes;
	}

	private static String base64EncodedBytes(byte[] bytes) {
		return DatatypeConverter.printBase64Binary(bytes);
	}
}
