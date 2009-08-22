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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

/**
 *
 * @author sirot
 */
public final class KexInitMessage extends SSHMessage
{
	public static final int SSH_MSG_KEXINIT = 20;

	/* Carbon copy of the encoded message from the peer */
	private byte[] encoding;

	private byte[] cookie;
	private String[] kexAlgorithms;
	private String[] serverHostKeyAlgorithms;
	private String[] encryptionAlgorithmsClientToServer;
	private String[] encryptionAlgorithmsServerToClient;
	private String[] macAlgorithmsClientToServer;
	private String[] macAlgorithmsServerToClient;
	private String[] compressionAlgorithmsClientToServer;
	private String[] compressionAlgorithmsServerToClient;
	private String[] languagesClientToServer;
	private String[] languagesServerToClient;
	private boolean firstKexPacketFollows;
	private int rfu;

	/**
	 * Creates a new empty <code>KeyExchangeInitPacket</code>
	 */
	public KexInitMessage()
	{
		super(SSH_MSG_KEXINIT);
	}

	@Override
	protected void decode(InputStream in) throws IOException
	{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		byte[] tmp = new byte[256];
		while (true) {
			int l = in.read(tmp);
			if (l == -1) {
				break;
			}
			out.write(tmp, 0, l);
		}
		encoding = out.toByteArray();
		in = new ByteArrayInputStream(encoding);
		cookie = Utils.decodeBytes(in, 16);
		kexAlgorithms = Utils.decodeNameList(in);
		serverHostKeyAlgorithms = Utils.decodeNameList(in);
		encryptionAlgorithmsClientToServer = Utils.decodeNameList(in);
		encryptionAlgorithmsServerToClient = Utils.decodeNameList(in);
		macAlgorithmsClientToServer = Utils.decodeNameList(in);
		macAlgorithmsServerToClient = Utils.decodeNameList(in);
		compressionAlgorithmsClientToServer = Utils.decodeNameList(in);
		compressionAlgorithmsServerToClient = Utils.decodeNameList(in);
		languagesClientToServer = Utils.decodeNameList(in);
		languagesServerToClient = Utils.decodeNameList(in);
		firstKexPacketFollows = Utils.decodeBoolean(in);
		rfu = Utils.decodeInt(in);
	}

	@Override
	protected void encode(OutputStream out) throws IOException
	{
		out.write(cookie);
		Utils.encodeNameList(out, kexAlgorithms);
		Utils.encodeNameList(out, serverHostKeyAlgorithms);
		Utils.encodeNameList(out, encryptionAlgorithmsClientToServer);
		Utils.encodeNameList(out, encryptionAlgorithmsServerToClient);
		Utils.encodeNameList(out, macAlgorithmsClientToServer);
		Utils.encodeNameList(out, macAlgorithmsServerToClient);
		Utils.encodeNameList(out, compressionAlgorithmsClientToServer);
		Utils.encodeNameList(out, compressionAlgorithmsServerToClient);
		Utils.encodeNameList(out, languagesClientToServer);
		Utils.encodeNameList(out, languagesServerToClient);
		Utils.encodeBoolean(out, firstKexPacketFollows);
		Utils.encodeInt(out, 0);
	}

	public byte[] getCookie()
	{
		return cookie;
	}

	public String[] getKexAlgorithms()
	{
		return kexAlgorithms;
	}

	public String[] getCompressionAlgorithmsClientToServer()
	{
		return compressionAlgorithmsClientToServer;
	}

	public String[] getCompressionAlgorithmsServerToClient()
	{
		return compressionAlgorithmsServerToClient;
	}

	public String[] getEncryptionAlgorithmsClientToServer()
	{
		return encryptionAlgorithmsClientToServer;
	}

	public String[] getEncryptionAlgorithmsServerToClient()
	{
		return encryptionAlgorithmsServerToClient;
	}

	public boolean isFirstKexPacketFollows()
	{
		return firstKexPacketFollows;
	}

	public String[] getLanguagesClientToServer()
	{
		return languagesClientToServer;
	}

	public String[] getLanguagesServerToClient()
	{
		return languagesServerToClient;
	}

	public String[] getMacAlgorithmsClientToServer()
	{
		return macAlgorithmsClientToServer;
	}

	public String[] getMacAlgorithmsServerToClient()
	{
		return macAlgorithmsServerToClient;
	}

	public String[] getServerHostKeyAlgorithms()
	{
		return serverHostKeyAlgorithms;
	}

	public void setCompressionAlgorithmsClientToServer(String[] algos)
	{
		this.compressionAlgorithmsClientToServer = algos;
	}

	public void setCompressionAlgorithmsServerToClient(String[] algos)
	{
		this.compressionAlgorithmsServerToClient = algos;
	}

	public void setCookie(byte[] cookie)
	{
		this.cookie = cookie;
	}

	public void setEncryptionAlgorithmsClientToServer(String[] algos)
	{
		this.encryptionAlgorithmsClientToServer = algos;
	}

	public void setEncryptionAlgorithmsServerToClient(String[] algos)
	{
		this.encryptionAlgorithmsServerToClient = algos;
	}

	public void setFirstKexPacketFollows(boolean firstKexPacketFollows)
	{
		this.firstKexPacketFollows = firstKexPacketFollows;
	}

	public void setKexAlgorithms(String[] kexAlgorithms)
	{
		this.kexAlgorithms = kexAlgorithms;
	}

	public void setLanguagesClientToServer(String[] langs)
	{
		this.languagesClientToServer = langs;
	}

	public void setLanguagesServerToClient(String[] langs)
	{
		this.languagesServerToClient = langs;
	}

	public void setMacAlgorithmsClientToServer(String[] algos)
	{
		this.macAlgorithmsClientToServer = algos;
	}

	public void setMacAlgorithmsServerToClient(String[] algos)
	{
		this.macAlgorithmsServerToClient = algos;
	}

	public void setServerHostKeyAlgorithms(String[] algos)
	{
		this.serverHostKeyAlgorithms = algos;
	}

	public byte[] getEncoding()
	{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			out.write(SSH_MSG_KEXINIT);
			if (encoding == null) {
				encode(out);
			} else {
				out.write(encoding);
			}
		} catch (IOException ioe) {
			/* Does not happen */
			throw new Error(ioe);
		}
		return out.toByteArray();
	}

	@Override
	public String toString()
	{
		StringBuilder sb = new StringBuilder();
		sb.append("SSH_MSG_KEXINIT, ");
		sb.append("cookie=" + Arrays.toString(cookie)).append(", ");
		sb.append("kex=" + Arrays.toString(kexAlgorithms)).append(", ");
		sb.append("host key algo=" + Arrays.toString(serverHostKeyAlgorithms)).append(", ");
		sb.append("encryption C->S=" + Arrays.toString(encryptionAlgorithmsClientToServer)).append(", ");
		sb.append("encryption S->C=" + Arrays.toString(encryptionAlgorithmsServerToClient)).append(", ");
		sb.append("mac C->S=" + Arrays.toString(macAlgorithmsClientToServer)).append(", ");
		sb.append("mac S->C=" + Arrays.toString(macAlgorithmsServerToClient)).append(", ");
		sb.append("compression C->S=" + Arrays.toString(compressionAlgorithmsClientToServer)).append(", ");
		sb.append("compression C->S=" + Arrays.toString(compressionAlgorithmsServerToClient)).append(", ");
		sb.append("lang C->S=" + Arrays.toString(languagesClientToServer)).append(", ");
		sb.append("lang S->C=" + Arrays.toString(languagesServerToClient)).append(", ");
		sb.append("kex packet follows=" + firstKexPacketFollows);
		return sb.toString();
	}
}