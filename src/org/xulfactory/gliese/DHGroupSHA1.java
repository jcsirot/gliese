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

import org.xulfactory.gliese.message.KexDHInitMessage;
import org.xulfactory.gliese.message.KexDHReplyMessage;
import org.xulfactory.gliese.util.GlieseLogger;
import org.xulfactory.gliese.util.Utils;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Random;

/**
 * Implementation of {@code diffie-helman-group1-sha1} and
 * {@code diffie-helman-group14-sha1} key exchange algorithms.
 *
 * @author sirot
 */
public class DHGroupSHA1 implements KeyExchangeAlgorithm
{
	private static final BigInteger P_1 = new BigInteger(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
		"FFFFFFFFFFFFFFFF", 16);

	private static final BigInteger P_14 = new BigInteger(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);

	private static final BigInteger G = new BigInteger("2");

	private static final String GROUP_1_NAME = "diffie-hellman-group1-sha1";
	private static final String GROUP_14_NAME = "diffie-hellman-group14-sha1";

	/**
	 * Namespace for diffie-hellman-group1-sha1 and
	 * diffie-hellman-group14-sha1 key exchange algorithms
	 */
	public static final String NAMESPACE = "diffie-hellman-sha1";

	/**
	 * Retrieves the {@code diffie-helman-group1-sha1} algorithm
	 */
	public static DHGroupSHA1 group1()
	{
		return new DHGroupSHA1(P_1, GROUP_1_NAME);
	}

	/**
	 * Retrieves the {@code diffie-helman-group14-sha1} algorithm
	 */
	public static DHGroupSHA1 group14()
	{
		return new DHGroupSHA1(P_14, GROUP_14_NAME);
	}

	private static MessageDigest dg;

	static {
		try {
			dg = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException nsae) {
			throw new Error("Message digest algorithm not found",
				nsae);
		}
	}

	private BigInteger x, e;
	private BigInteger p;
	private byte[] h;
	private BigInteger k;
	private final String name;

	/**
	 * Creates a new {@code DHGroupSHA1}.
	 * 
	 * @param p     a large prime for DH key exchange
	 * @param name  the algorithm name
	 */
	private DHGroupSHA1(BigInteger p, String name)
	{
		this.p = p;
		this.name = name;
	}

	/** @see KeyExchangeAlgorithm */
	public void process(SSHTransport transport,
		SSHPublicKeyFactory pkf, HostKeyVerifier hv)
		throws SSHException
	{
		transport.registerMessageClass(NAMESPACE, KexDHReplyMessage.class);
		Random rnd = new Random();
		BigInteger q = p.subtract(BigInteger.ONE).shiftRight(1);
		do {
			x = new BigInteger(q.bitLength(), rnd);
		} while (x.compareTo(q) >= 0);
		e = G.modPow(x, p);
		KexDHInitMessage init = new KexDHInitMessage();
		init.setE(e);
		transport.writeMessage(init);
		KexDHReplyMessage reply = (KexDHReplyMessage)transport
			.readMessage(NAMESPACE);

		BigInteger f = reply.getF();
		k = f.modPow(x, p);

		byte[] ks = reply.getKS();
		if (!hv.isTrusted(transport, reply.getKeyFormat(), ks)) {
			throw new SSHException("Server host key not trusted");
		}
		SSHPublicKey pubkey = pkf.decode(ks);
		Signature verifier = pubkey.getVerifier();

		dg.reset();
		dg.update(Utils.encodeBytes(transport.getVC()));
		dg.update(Utils.encodeBytes(transport.getVS()));
		dg.update(Utils.encodeBytes(transport.getIC()));
		dg.update(Utils.encodeBytes(transport.getIS()));
		dg.update(Utils.encodeBytes(reply.getKS()));
		dg.update(Utils.encodeBigInt(e));
		dg.update(Utils.encodeBigInt(f));
		dg.update(Utils.encodeBigInt(k));
		h = dg.digest();
		try {
			verifier.update(h);
			if(!verifier.verify(reply.getSigBlob())) {
				GlieseLogger.LOGGER.info("Server authentication failed.");
				throw new SSHException("Server authentication failed.");
			}
		} catch (SignatureException se) {
			// FIXME
		}
		dg.reset();
	}

	/** @see KeyExchangeAlgorithm */
	public BigInteger getSharedSecret()
	{
		return k;
	}

	/** @see KeyExchangeAlgorithm */
	public byte[] getExchangeHash()
	{
		return h;
	}

	/** @see KeyExchangeAlgorithm */
	public String getHashAlgorithm()
	{
		return "SHA-1";
	}

	/** @see KeyExchangeAlgorithm */
	public String getName()
	{
		return name;
	}
}
