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

package org.xulfactory.gliese.message;

import java.io.ByteArrayOutputStream;
import org.xulfactory.gliese.util.Utils;
import org.xulfactory.gliese.message.UserAuthRequestMessage.AuthenticationMethodCodec;
import org.xulfactory.gliese.message.UserAuthRequestMessage.AuthenticationMethodData;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 *
 * @author sirot
 */
public class PublicKeyMethodData implements AuthenticationMethodData
{
	public static final String METHOD = "publickey";

	private String algorithm;
	private byte[] pubkey;
	private byte[] signature;
	private boolean prepareTBS = false;

	public PublicKeyMethodData()
	{
	}

	public PublicKeyMethodData(String algorithm, byte[] pubkey)
	{
		this.algorithm = algorithm;
		this.pubkey = pubkey;
	}

	public PublicKeyMethodData(String algorithm, byte[] pubkey, byte[] signature)
	{
		this(algorithm, pubkey);
		this.signature = signature;
	}

	public String getMethod()
	{
		return METHOD;
	}

	public static class PublicKeyMethodCodec
		implements AuthenticationMethodCodec<PublicKeyMethodData>
	{
		public PublicKeyMethodData decode(InputStream in)
			throws IOException
		{
			PublicKeyMethodData p = new PublicKeyMethodData();
			boolean b = Utils.decodeBoolean(in);
			p.algorithm = Utils.decodeString(in);
			p.pubkey = Utils.decodeBytes(in);
			if (b) {
				p.signature = Utils.decodeBytes(in);
			}
			return p;
		}

		public void encode(OutputStream out, PublicKeyMethodData p)
			throws IOException
		{
			Utils.encodeBoolean(out,
				p.signature != null || p.prepareTBS);
			Utils.encodeString(out, p.algorithm);
			Utils.encodeBytes(out, p.pubkey);
			if (p.signature != null) {
				ByteArrayOutputStream baos
					= new ByteArrayOutputStream();
				Utils.encodeString(baos, p.algorithm);
				Utils.encodeBytes(baos, p.signature);
				Utils.encodeBytes(out, baos.toByteArray());
			}
		}
	}

	public String getAlgorithm()
	{
		return algorithm;
	}

	public byte[] getPubkey()
	{
		return pubkey;
	}

	public void setAlgorithm(String algorithm)
	{
		this.algorithm = algorithm;
	}

	public void setPubkey(byte[] pubkey)
	{
		this.pubkey = pubkey;
	}

	public void setSignature(byte[] signature)
	{
		this.signature = signature;
	}

	public byte[] getSignature()
	{
		return signature;
	}

	public void prepareTBS()
	{
		this.prepareTBS = true;
	}
}
