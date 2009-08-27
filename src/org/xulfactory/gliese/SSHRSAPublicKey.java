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

import org.xulfactory.gliese.util.GlieseLogger;
import org.xulfactory.gliese.util.Utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 * Implementation of {@code ssh-rsa} public key.
 *
 * @author sirot
 */
public class SSHRSAPublicKey implements SSHPublicKey
{
	private static final String NAME = "ssh-rsa";

	private BigInteger e;
	private BigInteger n;

	private SSHRSAPublicKey(byte[] encoding) throws SSHException
	{
		decode(encoding);
	}

	/**
	 * Creates a new {@code SSHRSAPublicKey} instance.
	 *
	 * @param n  the modulus
	 * @param e  the public exponent
	 */
	public SSHRSAPublicKey(BigInteger n, BigInteger e)
	{
		this.e = e;
		this.n = n;
	}

	private void decode(byte[] key) throws SSHException
	{
		ByteArrayInputStream in = new ByteArrayInputStream(key);
		try {
			String format = Utils.decodeString(in);
			if (!format.equals(NAME)) {
				GlieseLogger.LOGGER.error("Invalid host key algorithm: " + format);
				throw new SSHException("Invalid host key algorithm: " + format);
			}
			e = Utils.decodeBigInt(in);
			n = Utils.decodeBigInt(in);
		} catch (IOException ioe) {
			GlieseLogger.LOGGER.error("Host key invalid encoding", ioe);
			throw new SSHException("Host key invalid encoding", ioe);
		}
	}

	public byte[] encode()
	{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			Utils.encodeString(out, NAME);
			Utils.encodeBigInt(out, e);
			Utils.encodeBigInt(out, n);
		} catch (IOException ioe) {
			// does not happen
		}
		return out.toByteArray();		
	}

	public Signature getVerifier() throws SSHException
	{
		RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PublicKey k = kf.generatePublic(spec);
			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initVerify(k);
			return sig;
		} catch (NoSuchAlgorithmException nsae) {
			GlieseLogger.LOGGER.error("Signature verifier creation failed", nsae);
			throw new SSHException("Signature verifier creation failed", nsae);
		} catch (InvalidKeySpecException ikse) {
			GlieseLogger.LOGGER.error("Signature verifier creation failed", ikse);
			throw new SSHException("Signature verifier creation failed", ikse);
		} catch (InvalidKeyException ike) {
			GlieseLogger.LOGGER.error("Signature verifier creation failed", ike);
			throw new SSHException("Signature verifier creation failed", ike);
		}
	}

	/**
	 * Retrieves the public exponent.
	 *
	 * @return the public exponent
	 */
	public BigInteger getE()
	{
		return e;
	}

	/**
	 * Retrieves the modulus.
	 *
	 * @return the modulus
	 */
	public BigInteger getN()
	{
		return n;
	}

	public String getName()
	{
		return NAME;
	}

	public static class SSHRSAPublicKeyFactory implements SSHPublicKeyFactory
	{

		public String getName()
		{
			return NAME;
		}

		public SSHPublicKey decode(byte[] key) throws SSHException
		{
			return new SSHRSAPublicKey(key);
		}

	}
}
