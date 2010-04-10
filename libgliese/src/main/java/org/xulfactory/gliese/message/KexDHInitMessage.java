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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

/**
 *
 * @author sirot
 */
public class KexDHInitMessage extends SSHMessage
{
	public static final int ID = 30;

	private BigInteger e;

	public KexDHInitMessage()
	{
		super(ID);
	}

	@Override
	protected void decode(InputStream in) throws IOException
	{
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	protected void encode(OutputStream out) throws IOException
	{
		Utils.encodeBigInt(out, e);
	}

	public BigInteger getE()
	{
		return e;
	}

	public void setE(BigInteger e)
	{
		this.e = e;
	}

	@Override
	public String toString()
	{
		return "SSH_MSG_KEXDH_INIT";
	}
}
