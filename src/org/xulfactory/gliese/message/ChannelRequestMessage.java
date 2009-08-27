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
import org.xulfactory.gliese.message.ExecChannelRequest.ExecChannelRequestCodec;
import org.xulfactory.gliese.message.ExitStatusChannelRequest.ExitStatusChannelRequestCodec;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import org.xulfactory.gliese.message.UnknownChannelRequest.UnknownChannelRequestCodec;

/**
 *
 * @author sirot
 */
public class ChannelRequestMessage extends SSHMessage
{
	public static final int ID = 98;

	private int channelId;
	private String requestType;
	private ChannelRequest request;
	private boolean wantReply;

	private static Map<String, ChannelRequestCodec> requests
		= new HashMap<String, ChannelRequestCodec>();

	public static void register(String method, ChannelRequestCodec d)
	{
		requests.put(method, d);
	}

	static {
		register(ExecChannelRequest.TYPE, new ExecChannelRequestCodec());
		register(ExitStatusChannelRequest.TYPE, new ExitStatusChannelRequestCodec());
//		register(PublicKeyMethodData.METHOD, new PublicKeyMethodCodec());
//		register(KeyboardInteractiveMethodData.METHOD, new KeyboardInteractiveMethodCodec());
	}

	public ChannelRequestMessage()
	{
		super(ID);
	}

	@Override
	protected void decode(InputStream in) throws IOException
	{
		channelId = Utils.decodeInt(in);
		requestType = Utils.decodeString(in);
		wantReply = Utils.decodeBoolean(in);
		request = decode(requestType, in);
	}

	@Override
	protected void encode(OutputStream out) throws IOException
	{
		Utils.encodeInt(out, channelId);
		Utils.encodeString(out, request.getRequestType());
		Utils.encodeBoolean(out, wantReply);
		encode(out, request);
	}

	private ChannelRequest decode(String reqType, InputStream in)
		throws IOException
	{
		ChannelRequestCodec codec = requests.get(reqType);
		if (codec == null) {
			codec = new UnknownChannelRequestCodec();
		}
		return codec.decode(in);
	}

	private void encode(OutputStream out, ChannelRequest req)
		throws IOException
	{
		String reqType = req.getRequestType();
		ChannelRequestCodec codec = requests.get(reqType);
		codec.encode(out, req);
	}

	public int getChannelId()
	{
		return channelId;
	}

	public boolean getWantReply()
	{
		return wantReply;
	}

	public void setChannelId(int channelId)
	{
		this.channelId = channelId;
	}

	public void setWantReply(boolean wantReply)
	{
		this.wantReply = wantReply;
	}

	public ChannelRequest getRequest()
	{
		return request;
	}

	public void setRequest(ChannelRequest request)
	{
		this.request = request;
		this.requestType = request.getRequestType();
	}

	public String getRequestType()
	{
		return requestType;
	}

	public abstract static interface ChannelRequest
	{
		String getRequestType();
	}

	public abstract static interface ChannelRequestCodec<
		E extends ChannelRequest>
	{
		E decode(InputStream in) throws IOException;

		void encode(OutputStream out, E e) throws IOException;
	}

	public String toString()
	{
		StringBuilder sb = new StringBuilder();
		sb.append("SSH_MSG_CHANNEL_REQUEST");
		sb.append(", recipient channel: " + channelId);
		sb.append(", request type: " + requestType);
		return sb.toString();
	}
}
