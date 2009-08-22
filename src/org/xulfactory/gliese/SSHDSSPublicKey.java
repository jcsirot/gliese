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
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

/**
 * Implementation of {@code ssh-dss} public key.
 *
 * @author sirot
 */
public class SSHDSSPublicKey implements SSHPublicKey
{
	private static final String NAME = "ssh-dss";

	private BigInteger p;
	private BigInteger q;
	private BigInteger g;
	private BigInteger y;

	private SSHDSSPublicKey(byte[] encoding) throws SSHException
	{
		decode(encoding);
	}

	public SSHDSSPublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y)
	{
		this.p = p;
		this.q = q;
		this.g = g;
		this.y = y;
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
			p = Utils.decodeBigInt(in);
			q = Utils.decodeBigInt(in);
			g = Utils.decodeBigInt(in);
			y = Utils.decodeBigInt(in);
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
			Utils.encodeBigInt(out, p);
			Utils.encodeBigInt(out, q);
			Utils.encodeBigInt(out, g);
			Utils.encodeBigInt(out, y);
		} catch (IOException ioe) {
			// does not happen
		}
		return out.toByteArray();
	}

	public Signature getVerifier() throws SSHException
	{
		DSAPublicKeySpec spec = new DSAPublicKeySpec(y, p, q, g);
		try {
			KeyFactory kf = KeyFactory.getInstance("DSA");
			PublicKey k = kf.generatePublic(spec);
			Signature sig = Signature.getInstance("SHA1withDSA");
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

	BigInteger getP()
	{
		return p;
	}

	BigInteger getQ()
	{
		return q;
	}

	BigInteger getY()
	{
		return y;
	}
	BigInteger getG()
	{
		return g;
	}

	public String getName()
	{
		return NAME;
	}

	public static class SSHDSSPublicKeyFactory implements SSHPublicKeyFactory
	{

		public String getName()
		{
			return NAME;
		}

		public SSHPublicKey decode(byte[] key) throws SSHException
		{
			return new SSHDSSPublicKey(key);
		}

	}
}
