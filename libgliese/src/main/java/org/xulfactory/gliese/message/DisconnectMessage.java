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
public class DisconnectMessage extends SSHMessage
{
	public static final int ID = 1;

	public static final int HOST_NOT_ALLOWED_TO_CONNECT =             1;
	public static final int PROTOCOL_ERROR =                          2;
	public static final int KEY_EXCHANGE_FAILED =                     3;
	public static final int RESERVED =                                4;
	public static final int MAC_ERROR =                               5;
	public static final int COMPRESSION_ERROR =                       6;
	public static final int SERVICE_NOT_AVAILABLE =                   7;
	public static final int PROTOCOL_VERSION_NOT_SUPPORTED =          8;
	public static final int HOST_KEY_NOT_VERIFIABLE =                 9;
	public static final int CONNECTION_LOST =                        10;
	public static final int BY_APPLICATION =                         11;
	public static final int TOO_MANY_CONNECTIONS =                   12;
	public static final int AUTH_CANCELLED_BY_USER =                 13;
	public static final int NO_MORE_AUTH_METHODS_AVAILABLE =         14;
	public static final int ILLEGAL_USER_NAME =                      15;

	private int reasonCode;
	private String message;
	private String tag;

	public DisconnectMessage()
	{
		super(ID);
	}

	public DisconnectMessage(int reasonCode, String message, String tag)
	{
		super(ID);
		this.reasonCode = reasonCode;
		this.message = message;
		this.tag = tag;
	}

	@Override
	protected void decode(InputStream in) throws IOException
	{
		reasonCode = Utils.decodeInt(in);
		message = Utils.decodeStringUTF8(in);
		tag = Utils.decodeString(in);
	}

	@Override
	protected void encode(OutputStream out) throws IOException
	{
		Utils.encodeInt(out, reasonCode);
		Utils.encodeStringUTF8(out, message);
		Utils.encodeString(out, tag);
	}

	public int getReasonCode()
	{
		return reasonCode;
	}

	public String getMessage()
	{
		return message;
	}

	public String getTag()
	{
		return tag;
	}

	public void setReasonCode(int reasonCode)
	{
		this.reasonCode = reasonCode;
	}

	public void setMessage(String message)
	{
		this.message = message;
	}

	public void setTag(String tag)
	{
		this.tag = tag;
	}

	@Override
	public String toString()
	{
		StringBuilder sb = new StringBuilder();
		sb.append("SSH_MSG_DISCONNECT, ");
		sb.append("reason code=" + reasonCode).append(", ");
		sb.append("message=" + message).append(",");
		sb.append("lang tag=" + tag);
		return sb.toString();
	}
}
