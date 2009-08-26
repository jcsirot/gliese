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
import org.xulfactory.gliese.message.ChannelRequestMessage.ChannelRequest;
import org.xulfactory.gliese.message.ChannelRequestMessage.ChannelRequestCodec;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 *
 * @author sirot
 */
public class ExecChannelRequest implements ChannelRequest
{
	public static final String TYPE = "exec";

	private String command;

	private ExecChannelRequest()
	{
	}

	public ExecChannelRequest(String command)
	{
		this.command = command;
	}

	public String getRequestType()
	{
		return TYPE;
	}

	public static class ExecChannelRequestCodec
		implements ChannelRequestCodec<ExecChannelRequest>
	{
		public ExecChannelRequest decode(InputStream in)
			throws IOException
		{
			ExecChannelRequest p = new ExecChannelRequest();
			p.command = Utils.decodeStringUTF8(in);
			return p;
		}

		public void encode(OutputStream out, ExecChannelRequest p)
			throws IOException
		{
			Utils.encodeStringUTF8(out, p.command);
		}
	}

	public String getCommand()
	{
		return command;
	}

	public void setCommand(String command)
	{
		this.command = command;
	}
}
