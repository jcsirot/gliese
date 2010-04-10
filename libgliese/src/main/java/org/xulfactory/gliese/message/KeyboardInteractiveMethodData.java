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
public class KeyboardInteractiveMethodData implements AuthenticationMethodData
{
	public static final String METHOD
		= "keyboard-interactive";

	private String submethods;

	private KeyboardInteractiveMethodData()
	{
	}

	public KeyboardInteractiveMethodData(String submethods)
	{
		this.submethods = submethods;
	}

	public String getMethod()
	{
		return METHOD;
	}

	public static class KeyboardInteractiveMethodCodec
		implements AuthenticationMethodCodec<KeyboardInteractiveMethodData>
	{
		public KeyboardInteractiveMethodData decode(InputStream in)
			throws IOException
		{
			KeyboardInteractiveMethodData p = new KeyboardInteractiveMethodData();
			Utils.decodeString(in);
			p.submethods = Utils.decodeStringUTF8(in);
			return p;
		}

		public void encode(OutputStream out, KeyboardInteractiveMethodData p)
			throws IOException
		{
			Utils.encodeString(out, "");
			Utils.encodeStringUTF8(out, p.submethods);
		}
	}

	public String getSubMethods()
	{
		return submethods;
	}

	public void setSubMethods(String submethods)
	{
		this.submethods = submethods;
	}
}
