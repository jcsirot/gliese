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

import org.xulfactory.gliese.util.Utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

/**
 *
 * @author sirot
 */
public class KexDHReplyMessage extends SSHMessage
{
	public static final int ID = 31;

	public KexDHReplyMessage()
	{
		super(ID);
	}

	private byte[] KS;
	private String keyFormat;
	private BigInteger f;
	private byte[] signature;
	private String sigFormat;
	private byte[] sigBlob;

	@Override
	protected void decode(InputStream in) throws IOException
	{
		KS = Utils.decodeBytes(in);
		ByteArrayInputStream in2 = new ByteArrayInputStream(KS);
		keyFormat = Utils.decodeString(in2);
		f = Utils.decodeBigInt(in);
		signature = Utils.decodeBytes(in);
		in2 = new ByteArrayInputStream(signature);
		sigFormat = Utils.decodeString(in2);
		sigBlob = Utils.decodeBytes(in2);
	}

	@Override
	protected void encode(OutputStream out) throws IOException
	{
		throw new UnsupportedOperationException("Not supported yet.");
	}

	public byte[] getKS()
	{
		return KS;
	}

	public BigInteger getF()
	{
		return f;
	}

	public byte[] getSignature()
	{
		return signature;
	}

	public String getKeyFormat()
	{
		return keyFormat;
	}

	public String getSigFormat()
	{
		return sigFormat;
	}

	public byte[] getSigBlob()
	{
		return sigBlob;
	}

	@Override
	public String toString()
	{
		return "SSH_MSG_KEXDH_REPLY";
	}
}
