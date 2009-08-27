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
public class ChannelOpenConfirmationMessage extends SSHMessage
{
	public static final int ID = 91;

	private int recipientChannelId;
	private int senderChannelId;
	private int initialWindowSize;
	private int maxPacketSize;

	public ChannelOpenConfirmationMessage()
	{
		super(ID);
	}

	@Override
	protected void decode(InputStream in) throws IOException
	{
		recipientChannelId = Utils.decodeInt(in);
		senderChannelId = Utils.decodeInt(in);
		initialWindowSize = Utils.decodeInt(in);
		maxPacketSize = Utils.decodeInt(in);
	}

	@Override
	protected void encode(OutputStream out) throws IOException
	{
		Utils.encodeInt(out, recipientChannelId);
		Utils.encodeInt(out, senderChannelId);
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

	public int getRecipientChannelId()
	{
		return recipientChannelId;
	}

	public int getSenderChannelId()
	{
		return senderChannelId;
	}

	public void setInitialWindowSize(int initialWindowSize)
	{
		this.initialWindowSize = initialWindowSize;
	}

	public void setMaxPacketSize(int maxPacketSize)
	{
		this.maxPacketSize = maxPacketSize;
	}

	public void setRecipientChannelId(int recipientChannelId)
	{
		this.recipientChannelId = recipientChannelId;
	}

	public void setSenderChannelId(int senderChannelId)
	{
		this.senderChannelId = senderChannelId;
	}

	public String toString()
	{
		StringBuilder sb = new StringBuilder();
		sb.append("SSH_MSG_CHANNEL_CONFIRMATION, ");
		sb.append("recipient=" + recipientChannelId);
		sb.append(", sender=" + senderChannelId);
		sb.append(", window init size=" + initialWindowSize);
		sb.append(", packet max size=" + maxPacketSize);
		return sb.toString();
	}
}
