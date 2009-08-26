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
import org.xulfactory.gliese.message.ChannelRequestMessage.ChannelRequest;
import org.xulfactory.gliese.message.ChannelRequestMessage.ChannelRequestCodec;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 *
 * @author sirot
 */
public class UnknownChannelRequest implements ChannelRequest
{
	private byte[] encoding;

	private UnknownChannelRequest()
	{
	}

	public String getRequestType()
	{
		return null;
	}

	public static class UnknownChannelRequestCodec
		implements ChannelRequestCodec<UnknownChannelRequest>
	{
		public UnknownChannelRequest decode(InputStream in)
			throws IOException
		{
			UnknownChannelRequest p = new UnknownChannelRequest();
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			do {
				byte[] b = new byte[1024];
				int len = in.read(b);
				if (len == -1) {
					break;
				}
				out.write(b, 0, len);
			} while (true);
			p.encoding = out.toByteArray();
			return p;
		}

		public void encode(OutputStream out, UnknownChannelRequest p)
			throws IOException
		{
			out.write(p.encoding);
		}
	}

	public byte[] getEncoding()
	{
		return encoding;
	}
}
