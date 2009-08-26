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
public class ChannelWindowsAdjustMessage extends SSHMessage
{
	public static final int ID = 93;

	private int channelId;
	private long bytesToAdd;

	public ChannelWindowsAdjustMessage()
	{
		super(ID);
	}

	public ChannelWindowsAdjustMessage(int channelId, long bytesToAdd)
	{
		this();
		this.channelId = channelId;
		this.bytesToAdd = bytesToAdd;
	}

	@Override
	protected void decode(InputStream in) throws IOException
	{
		channelId = Utils.decodeInt(in);
		bytesToAdd = Utils.decodeInt(in);
	}

	@Override
	protected void encode(OutputStream out) throws IOException
	{
		Utils.encodeInt(out, channelId);
		Utils.encodeInt(out, bytesToAdd);
	}

	public long getBytesToAdd()
	{
		return bytesToAdd;
	}

	public int getChannelId()
	{
		return channelId;
	}

	public void setBytesToAdd(long bytesToAdd)
	{
		this.bytesToAdd = bytesToAdd;
	}

	public void setChannelId(int channelId)
	{
		this.channelId = channelId;
	}

	public String toString()
	{
		StringBuilder sb = new StringBuilder();
		sb.append("SSH_MSG_CHANNEL_WINDOW_ADJUST");
		sb.append(", recipient channel: ").append(channelId);
		sb.append(", bytes to add: ").append(bytesToAdd);
		return sb.toString();
	}
}
