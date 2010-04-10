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
import org.xulfactory.gliese.message.UserAuthRequestMessage.AuthenticationMethodCodec;
import org.xulfactory.gliese.message.UserAuthRequestMessage.AuthenticationMethodData;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 *
 * @author sirot
 */
public class PasswordMethodData implements AuthenticationMethodData
{
	public static final String METHOD = "password";

	private char[] password;

	private PasswordMethodData()
	{
	}

	public PasswordMethodData(char[] password)
	{
		this.password = password;
	}

	public String getMethod()
	{
		return METHOD;
	}

	public static class PasswordMethodCodec
		implements AuthenticationMethodCodec<PasswordMethodData>
	{
		public PasswordMethodData decode(InputStream in)
			throws IOException
		{
			PasswordMethodData p = new PasswordMethodData();
			Utils.decodeBoolean(in);
			p.password = Utils.decodeStringUTF8(in).toCharArray();
			return p;
		}

		public void encode(OutputStream out, PasswordMethodData p)
			throws IOException
		{
			Utils.encodeBoolean(out, false);
			Utils.encodeStringUTF8(out, new String(p.password));
		}
	}

	public char[] getPassword()
	{
		return password;
	}

	public void setPassword(char[] password)
	{
		this.password = password;
	}
}
