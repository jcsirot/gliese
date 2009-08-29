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

/**
 *
 * @author sirot
 */
public class ChannelDataMessage extends SSHMessage
{
	public static final int ID = 94;

	private int channelId;
	private byte[] data;

	public ChannelDataMessage()
	{
		super(ID);
	}

	@Override
	protected void decode(InputStream in) throws IOException
	{
		channelId = Utils.decodeInt(in);
		data = Utils.decodeBytes(in);
	}

	@Override
	protected void encode(OutputStream out) throws IOException
	{
		Utils.encodeInt(out, channelId);
		Utils.encodeBytes(out, data);
	}

	public int getChannelId()
	{
		return channelId;
	}

	public byte[] getData()
	{
		return data;
	}

	public void setChannelId(int channelId)
	{
		this.channelId = channelId;
	}

	public void setData(byte[] buf)
	{
		setData(buf, 0, buf.length);
	}

	public void setData(byte[] buf, int off, int len)
	{
		this.data = new byte[len];
		System.arraycopy(buf, off, data, 0, len);
	}

	public String toString()
	{
		StringBuilder sb = new StringBuilder();
		sb.append("SSH_MSG_CHANNEL_DATA, ");
		sb.append("recipient=" + channelId);
		sb.append(", data length=" + data.length);
		return sb.toString();
	}
}
