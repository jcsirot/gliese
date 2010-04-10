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
public class ChannelOpenMessage extends SSHMessage
{
	/** SSH_MSG_CHANNEL_OPEN */
	public static final int ID = 90;

	private String channelType;
	private int channelId;
	private int initialWindowSize;
	private int maxPacketSize;

	public ChannelOpenMessage()
	{
		super(ID);
	}

	/**
	 * Creates a {@code SSH_MSG_CHANNEL_OPEN} message.
	 *
	 * @param type  the channel type (session, x11, forwarded-tcpip...)
	 * @param id  the local channel unique identifier
	 * @param initialWindowSize  the number of bytes of channel data can
	 *        be received from the server without adjusting the window
	 * @param maxPacketSize  the maximum size of an individual data packet
	 *        that can be sent received
	 */
	public ChannelOpenMessage(String type, int id,
		int initialWindowSize, int maxPacketSize)
	{
		this();
		this.channelType = type;
		this.channelId = id;
		this.initialWindowSize = initialWindowSize;
		this.maxPacketSize = maxPacketSize;
	}

	/** @see SSHMessage */
	@Override
	protected void decode(InputStream in) throws IOException
	{
		channelType = Utils.decodeString(in);
		channelId = Utils.decodeInt(in);
		initialWindowSize = Utils.decodeInt(in);
		maxPacketSize = Utils.decodeInt(in);
	}

	/** @see SSHMessage */
	@Override
	protected void encode(OutputStream out) throws IOException
	{
		Utils.encodeString(out, channelType);
		Utils.encodeInt(out, channelId);
		Utils.encodeInt(out, initialWindowSize);
		Utils.encodeInt(out, maxPacketSize);
	}

	public int getInitialWindowSize()
	{
		return initialWindowSize;
	}

	public int getMaxPacketSize()
	{
		return maxPacketSize;
	}

	public int getChannelId()
	{
		return channelId;
	}

	public String getChannelType()
	{
		return channelType;
	}

	public void setInitialWindowSize(int initialWindowSize)
	{
		this.initialWindowSize = initialWindowSize;
	}

	public void setMaxPacketSize(int maxPacketSize)
	{
		this.maxPacketSize = maxPacketSize;
	}

	public void setChannelId(int channelId)
	{
		this.channelId = channelId;
	}

	public void setChannelType(String channelType)
	{
		this.channelType = channelType;
	}

	/** @see Object */
	public String toString()
	{
		StringBuilder sb = new StringBuilder();
		sb.append("SSH_MSG_CHANNEL_OPEN, ");
		sb.append("type=" + channelType);
		sb.append(", id=" + channelId);
		sb.append(", window init size=" + initialWindowSize);
		sb.append(", packet max size=" + maxPacketSize);
		return sb.toString();
	}
}
