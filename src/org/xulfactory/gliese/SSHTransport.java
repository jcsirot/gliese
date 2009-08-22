/*
 *  Copyright 2009 Jean-Christophe Sirot <sirot@xulfactory.org>.
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  under the License.
 */

package org.xulfactory.gliese;

import org.xulfactory.gliese.message.PacketFactory;
import org.xulfactory.gliese.message.KexInitMessage;
import org.xulfactory.gliese.message.NewKeysMessage;
import org.xulfactory.gliese.message.SSHMessage;
import org.xulfactory.gliese.util.Utils;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import org.xulfactory.gliese.message.DebugMessage;
import org.xulfactory.gliese.message.DisconnectMessage;
import org.xulfactory.gliese.util.GlieseLogger;

/**
 * Handler on the transport layer.
 *
 * @author sirot
 */
public class SSHTransport
{
	private static final String VER_EX_REGEXP = "^SSH-(\\S+)-(\\S+)(\\s+\\S)*";
	private static final String VERSION = "SSH-2.0-Gliese_{0} {1}";

	private static final <T extends SSHAlgorithm> String[] listNames(List<T> algos)
	{
		List<String> names = new ArrayList<String>();
		for (T algo: algos) {
			names.add(algo.getName());
		}
		return names.toArray(new String[0]);
	}

	private static final  <T extends SSHAlgorithm> T getAlgorithm(List<T> algos, String name)
		throws SSHException
	{
		for (T algo: algos) {
			if (algo.getName().equals(name)) {
				return algo;
			}
		}
		throw new SSHException("Algorithm not found: " + name);
	}

	private Random rnd = new Random();
	/** Transmitter of SSH messages */
	private PacketFactory factory;
	/** Server optional banner */
	private String banner;
	private String protoVersion;
	private String softwareVersion;
	/** Client hello string encoding */
	private byte[] vc;
	/** Server hello string encoding */
	private byte[] vs;
	/** Encoding of the client key exchange init message */
	private byte[] ic;
	/** Encoding of the server key exchange init message */
	private byte[] is;
	/** Peer inet address */
	private final InetAddress address;
	/** Connected socket to the peer */
	private final Socket socket;

	/** List of supported algorithm for the key exchange */
	private SSHAlgorithms algos;
	/** Peer public key verification callback */
	private final HostKeyVerifier hv;
	boolean guess = true;
	/** The session id generated after the initial key exchange */
	private byte[] sessionId = null;

	/* Negotiated algorithms */
	private String kexAlgo;
	private String hostKeyAlgo;
	private String encryptionCS;
	private String encryptionSC;
	private String integrityCS;
	private String integritySC;

	private Map<String, CipherAlgorithm> cipherAlgos;
	private Map<String, MacAlgorithm> macAlgos;

	SSHTransport(String host, int port, SSHAlgorithms algos, HostKeyVerifier hv)
		throws IOException
	{
		this.algos = algos;
		InetSocketAddress addr = new InetSocketAddress(host, port);
		socket = new Socket();
		socket.connect(addr);
		address = socket.getInetAddress();
		this.hv = hv != null ? hv : new ConsoleHostKeyVerifier();
	}

	/**
	 * Creates a new {@code SSHTransport}.
	 *
	 * @param s  the socket
	 * @param algos  the supported algorithms
	 * @throws SSHException
	 * @throws SSHTimeoutException on timeout
	 */
	SSHTransport(Socket s, SSHAlgorithms algos, HostKeyVerifier hv)
	{
		this.algos = algos;
		address = s.getInetAddress();
		this.socket = s;
		this.hv = hv != null ? hv : new ConsoleHostKeyVerifier();
	}

	void openConnection() throws SSHException
	{
		try {
			initConnection();
		} catch (IOException ioe) {
			GlieseLogger.LOGGER.error("I/O error", ioe);
			throw new SSHException("I/O error", ioe);
		}
		try {
			exchangeKey();
		} catch (SSHException se) {
			GlieseLogger.LOGGER.error(se.getMessage(), se);
			throw se;
		}
	}

	private void initConnection() throws SSHException, IOException
	{
		InputStream in = socket.getInputStream();
		OutputStream out = socket.getOutputStream();
		initAlgorithms(algos);
		BufferedReader br = new BufferedReader(
			new InputStreamReader(in, "ASCII"));
		String line = null;
		StringBuilder sb = new StringBuilder();
		for (;;) {
			line = br.readLine();
			if (line.startsWith("SSH-")) {
				break;
			} else {
				sb.append(line).append("\r\n");
			}
		}
		banner = sb.toString();
		Pattern p = Pattern.compile(VER_EX_REGEXP);
		Matcher m = p.matcher(line);
		if (!m.find()) {
			throw new SSHException("Invalid server");
		}
		protoVersion = m.group(1);
		softwareVersion = m.group(2);
		if (!protoVersion.equals("2.0")) {
			throw new SSHException("Unsupported protocol version: " + protoVersion);
		}
		vs = line.getBytes("ASCII");

		String thisVersion = MessageFormat.format(VERSION, "0.1",
				System.getProperty("os.name") + "-" +
				System.getProperty("os.arch"));

		vc = thisVersion.getBytes("ASCII");
		out.write(vc);
		out.write('\r');
		out.write('\n');
		out.flush();		
		factory = new PacketFactory(in, out);
	}

	private void exchangeKey() throws SSHException
	{
		KexInitMessage clientKex = new KexInitMessage();
		byte[] cookie = new byte[16];
		rnd.nextBytes(cookie);
		clientKex.setCookie(cookie);
		clientKex.setKexAlgorithms(listNames(algos.getKexAlgorithms()));
		clientKex.setEncryptionAlgorithmsClientToServer(listNames(algos.getEncryptionAlgorithms()));
		clientKex.setEncryptionAlgorithmsServerToClient(listNames(algos.getEncryptionAlgorithms()));
		clientKex.setMacAlgorithmsClientToServer(listNames(algos.getMacAlgorithms()));
		clientKex.setMacAlgorithmsServerToClient(listNames(algos.getMacAlgorithms()));
		clientKex.setCompressionAlgorithmsClientToServer(new String[] {"none"});
		clientKex.setCompressionAlgorithmsServerToClient(new String[] {"none"});
		clientKex.setLanguagesClientToServer(new String[0]);
		clientKex.setLanguagesServerToClient(new String[0]);
		clientKex.setServerHostKeyAlgorithms(listNames(algos.getServerHostKeyAlgorithms()));
		clientKex.setFirstKexPacketFollows(false);
		writeMessage(clientKex);

		KexInitMessage serverKex = (KexInitMessage)readMessage();

		ic = clientKex.getEncoding();
		is = serverKex.getEncoding();

		kexAlgo = selectAlgorithm(serverKex.getKexAlgorithms(),
			clientKex.getKexAlgorithms(), true);
		if (kexAlgo == null) {
			throw new SSHException("Unsupported key exchange algorithm.");
		}
		hostKeyAlgo = selectAlgorithm(
			serverKex.getServerHostKeyAlgorithms(),
			clientKex.getServerHostKeyAlgorithms(), true);
		if (hostKeyAlgo == null) {
			throw new SSHException("Unsupported host key algorithm.");
		}
		encryptionCS = selectAlgorithm(
			serverKex.getEncryptionAlgorithmsClientToServer(),
			clientKex.getEncryptionAlgorithmsClientToServer(),
			false);
		encryptionSC = selectAlgorithm(
			serverKex.getEncryptionAlgorithmsServerToClient(),
			clientKex.getEncryptionAlgorithmsServerToClient(),
			false);
		integrityCS = selectAlgorithm(
			serverKex.getMacAlgorithmsClientToServer(),
			clientKex.getMacAlgorithmsClientToServer(),
			false);
		integritySC = selectAlgorithm(
			serverKex.getMacAlgorithmsServerToClient(),
			clientKex.getMacAlgorithmsServerToClient(),
			false);

		GlieseLogger.LOGGER.info(String.format(
			"Negotiated algorithms: %s %s", kexAlgo, hostKeyAlgo));
		GlieseLogger.LOGGER.info(String.format(
			"Negotiated algorithms client->server: %s %s %s",
			encryptionCS, integrityCS, "none"));
		GlieseLogger.LOGGER.info(String.format(
			"Negotiated algorithms server->client: %s %s %s",
			encryptionSC, integritySC, "none"));

		if (serverKex.isFirstKexPacketFollows() && !guess) {
			/* when guess is wrong ignore the next packet */
			readMessage();
		}

		KeyExchangeAlgorithm dh = getAlgorithm(
			algos.getKexAlgorithms(), kexAlgo);
		SSHPublicKeyFactory pkf = getAlgorithm(
			algos.getServerHostKeyAlgorithms(), hostKeyAlgo);
		dh.process(this, pkf, hv);

		if (sessionId == null) {
			sessionId = dh.getExchangeHash();
		}

		writeMessage(new NewKeysMessage());
		readMessage(NewKeysMessage.ID);

		updateCrypto(dh.getExchangeHash(),
			dh.getSharedSecret(),
			dh.getHashAlgorithm());
	}

	/**
	 * Selects the algorithm from the key exchange init messages.
	 *
	 * @param server  the server algorithm name list
	 * @param client  the client algorithm name list
	 * @param withGuess  indicates whether this algorithm negociation
	 *        impacts the guess
	 * @return
	 */
	private String selectAlgorithm(String[] server, String[] client, boolean withGuess)
	{
		if (server[0].equals(client[0])) {
			if (withGuess) {
				guess = guess & true;
			}
			return server[0];
		} else {
			if (withGuess) {
				guess = false;
			}
			List<String> algorithms = Arrays.asList(server);
			for (String a: client) {
				if (algorithms.contains(a)) {
					return a;
				}
			}
		}
		return null;
	}

	/**
	 * Initializes the algorithms and uses them.
	 *
	 * @param h  the exchange hash
	 * @param k  the shared secret
	 * @param hashAlgo  the digest algorithm defined by the exchange method
	 */
	private void updateCrypto(byte[] h, BigInteger k, String hashAlgo)
	{
		MessageDigest dg;
		try {
			dg = MessageDigest.getInstance(hashAlgo);
		} catch (NoSuchAlgorithmException nsae) {
			/* Does not happen. */
			throw new Error(nsae);
		}

		CipherAlgorithm ccsh = cipherAlgos.get(encryptionCS);
		CipherAlgorithm csch = cipherAlgos.get(encryptionSC);
		MacAlgorithm mcsh = macAlgos.get(integrityCS);
		MacAlgorithm msch = macAlgos.get(integritySC);

		byte[] ivcs = derivation(k, h, (byte)65, sessionId, ccsh.getBlockLength(), dg);
		byte[] ivsc = derivation(k, h, (byte)66, sessionId, csch.getBlockLength(), dg);
		byte[] keycs = derivation(k, h, (byte)67, sessionId, ccsh.getKeyLength(), dg);
		byte[] keysc = derivation(k, h, (byte)68, sessionId, csch.getKeyLength(), dg);
		byte[] maccs = derivation(k, h, (byte)69, sessionId, mcsh.getBlockLength(), dg);
		byte[] macsc = derivation(k, h, (byte)70, sessionId, msch.getBlockLength(), dg);

		Cipher ccs = ccsh.getInstance(keycs, ivcs, Cipher.ENCRYPT_MODE);
		Cipher csc = csch.getInstance(keysc, ivsc, Cipher.DECRYPT_MODE);
		Mac mcs = mcsh.getInstance(maccs);
		Mac msc = msch.getInstance(macsc);

		factory.newKeys(ccs, csc, mcs, msc);
	}

	/**
	 * Computes the secret key or IV from the exchange key result
	 *
	 * @param k  the kex shared secret
	 * @param h  the kex exchange hash
	 * @param x  should be 'A', 'B', 'C', 'D', 'E' or 'F' depending on the
	 *           computed data.
	 * @param sessionId  the session identifier
	 * @param len  the length of data to compute in bytes
	 * @return
	 */
	private byte[] derivation(BigInteger k, byte[] h, byte x,
			byte[] sessionId, int len, MessageDigest dg)
	{
		byte[] data = new byte[len];
		dg.reset();
		dg.update(Utils.encodeBigInt(k));
		dg.update(h);
		dg.update(x);
		dg.update(sessionId);
		byte[] km = dg.digest();
		ByteArrayOutputStream key = new ByteArrayOutputStream();
		key.write(km, 0, km.length);
		if (key.size() < len) {
			do {
				dg.reset();
				dg.update(Utils.encodeBigInt(k));
				dg.update(h);
				dg.update(key.toByteArray());
				km = dg.digest();
				key.write(km, 0, km.length);
			} while (key.size() < len);
		}
		System.arraycopy(key.toByteArray(), 0, data, 0, len);
		return data;
	}

	private void initAlgorithms(SSHAlgorithms algos)
	{
		cipherAlgos = new HashMap<String, CipherAlgorithm>();
		macAlgos = new HashMap<String, MacAlgorithm>();
		for (CipherAlgorithm algo: algos.getEncryptionAlgorithms()) {
			cipherAlgos.put(algo.getName(), algo);
		}
		for (MacAlgorithm algo: algos.getMacAlgorithms()) {
			macAlgos.put(algo.getName(), algo);
		}
	}

	/**
	 * Sends a message to the server.
	 *
	 * @param msg  the message
	 * @throws SSHException if an error occurred
	 */
	public void writeMessage(SSHMessage msg) throws SSHException
	{
		factory.writeMessage(msg);
	}

	/**
	 * Reads a message from the server and checks if the message id is
	 * among the list. Blocks until a message is available.
	 *
	 * @param ids the list of expected message id
	 * @return the message
	 * @throws SSHException if an error occurred or the read message
	 *         ID is not among the expected IDs
	 */
	public SSHMessage readMessage(int... ids) throws SSHException
	{
		return factory.readMessage(ids);
	}

	public SSHMessage readMessage(String namespace, int... ids)
		throws SSHException
	{
		return factory.readMessage(namespace, ids);
	}

	/**
	 * Reads a message from the server. Blocks until a message is
	 * available or timeout is reached.
	 *
	 * @return the message
	 * @throws SSHException if an error occurred
	 */
	public SSHMessage readMessage(String namespace) throws SSHException
	{
		SSHMessage m;
		do {
			m = factory.readMessage(namespace);
			if (m.getID() == DisconnectMessage.ID) {
				DisconnectMessage msg = (DisconnectMessage)m;
				GlieseLogger.LOGGER.info("Disconnect message received: " + msg);
				close();
				throw new SSHException(String.format(
					"%s (reason code=%d)", msg.getMessage(),
					msg.getReasonCode()));
			} else if (m.getID() == DebugMessage.ID) {
				DebugMessage msg = (DebugMessage)m;
				if (msg.isAlwaysDisplay()) {
					GlieseLogger.LOGGER.info("Debug message: " + msg.getMessage());
				} else {
					GlieseLogger.LOGGER.debug("Debug message: " + msg.getMessage());
				}
			} else {
				break;
			}
		} while (true);
		return m;
	}

	/**
	 * Reads a message from the server. Blocks until a message is
	 * available.
	 *
	 * @return the message
	 * @throws SSHException if an error occurred
	 */
	public SSHMessage readMessage() throws SSHException
	{
		return readMessage((String)null);
	}

	/**
	 * Register a type of message for decoding in the default namespace.
	 *
	 * @param klass the message class
	 */
	public void registerMessageClass(Class<? extends SSHMessage> klass)
	{
		factory.register(klass);
	}

	/**
	 * Register a type of message for decoding in the given namespace.
	 *
	 * @param namespace  the namespace
	 * @param klass  the message class
	 */
	public void registerMessageClass(String namespace,
		Class<? extends SSHMessage> klass)
	{
		factory.register(namespace, klass);
	}

	/**
	 * Retrieves the exchanged client's SSH_MSG_KEXINIT message.
	 *
	 * @return the client's SSH_MSG_KEXINIT message
	 */
	public byte[] getIC()
	{
		return ic;
	}

	/**
	 * Retrieves the exchanged server's SSH_MSG_KEXINIT message.
	 *
	 * @return the server's SSH_MSG_KEXINIT message
	 */
	public byte[] getIS()
	{
		return is;
	}

	/**
	 * Retrieves the client identification string.
	 *
	 * @return the client identification string
	 */
	public byte[] getVC()
	{
		return vc;
	}

	/**
	 * Retrieves the server identification string.
	 *
	 * @return the server identification string
	 */
	public byte[] getVS()
	{
		return vs;
	}

	public byte[] getSessionId()
	{
		return sessionId;
	}

	public String getEncryptionAlgorithmClientToServer()
	{
		return encryptionCS;
	}

	public String getEncryptionAlgorithmServerToClient()
	{
		return encryptionSC;
	}

	/**
	 * Retrieves the negociated host key algorithm.
	 *
	 * @return  the host key algorithm
	 */
	public String getHostKeyAlgorithm()
	{
		return hostKeyAlgo;
	}

	public String getMacAlgorithmClientToServer()
	{
		return integrityCS;
	}

	public String getMacAlgorithmServerToClient()
	{
		return integritySC;
	}

	/**
	 * Retrieves the negociated key exchange algorithm.
	 *
	 * @return  the key exchange algorithm
	 */
	public String getKeyExchangeAlgorithm()
	{
		return kexAlgo;
	}

	public InetAddress getPeer()
	{
		return address;
	}

	public String getPeerSoftware()
	{
		return softwareVersion;
	}

	public String getPeerProtocolVersion()
	{
		return protoVersion;
	}

	public void close()
	{
		try {
			socket.close();
		} catch (IOException ioe) {
			GlieseLogger.LOGGER.error("I/O error on socket close", ioe);
		}
	}
}
