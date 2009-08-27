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

import org.xulfactory.gliese.SSHException;
import org.xulfactory.gliese.util.Utils;
import org.xulfactory.gliese.util.GlieseLogger;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.Mac;

/**
 * <p>
 * Packet reader and writer.
 * 
 * The {@code PacketFactory} reads the packet from the server, decode
 * the messages and instanciate the correct object according to the message
 * type and the optional namespace.
 *
 * The {@code PacketFactory} class also handles encryption, decryption,
 * integrity and compression (NYI) of the packets.
 * </p>
 *
 *
 * @author sirot
 */
public class PacketFactory
{
	private Map<String, Map<Integer, Class<? extends SSHMessage>>> types;
	private InputStream oin;
	private OutputStream oout;
	private final SSHInputStream in;
	private final SSHOutputStream out;
	private Random rnd;
	private int blockSizeCS = 8;
	private int blockSizeSC = 8;

	/**
	 * Creates a {@code PacketFactory} instance.
	 *
	 * @param in  the input stream
	 * @param out  the output stream
	 */
	public PacketFactory(InputStream in, OutputStream out)
	{
		this.oin = new BufferedInputStream(in);
		this.in = new SSHInputStream(oin);
		this.oout = new BufferedOutputStream(out);
		this.out = new SSHOutputStream(oout);
		this.rnd = new Random();
		this.types = new HashMap<String,
			Map<Integer, Class<? extends SSHMessage>>>();
		registerIncomingMessages();
	}

	private void registerIncomingMessages()
	{
		register(KexInitMessage.class);
		register(NewKeysMessage.class);
		register(DebugMessage.class);
		register(DisconnectMessage.class);
		register(ServiceRequestMessage.class);
		register(ServiceAcceptMessage.class);
		register(UserAuthFailureMessage.class);
		register(UserAuthSuccessMessage.class);
		register(UserAuthBannerMessage.class);
		register(UserAuthPublicKeyOk.class);
		register(ChannelOpenConfirmationMessage.class);
		register(ChannelWindowsAdjustMessage.class);
		register(ChannelSuccessMessage.class);
		register(ChannelFailureMessage.class);
		register(ChannelRequestMessage.class);
		register(ChannelDataMessage.class);
		register(ChannelExtendedDataMessage.class);
		register(ChannelEOFMessage.class);
		register(ChannelCloseMessage.class);
	}

	/**
	 * register a new SSH message class in the default namespace.
	 *
	 * @param klass  the message class
	 */
	public <T extends SSHMessage> void register(Class<T> klass)
	{
		register(null, klass);
	}

	/**
	 * register a new SSH message class in the given namespace.
	 *
	 * @param namespace  the message namespace
	 * @param klass  the message class
	 */
	public <T extends SSHMessage> void register(String namespace, Class<T> klass)
	{
		Map<Integer, Class<? extends SSHMessage>> map
			= types.get(namespace);
		if (map == null) {
			map = new HashMap<Integer, Class<? extends SSHMessage>>();
			types.put(namespace, map);
		}
		try {
			SSHMessage message = klass.newInstance();
			int id = message.getID();
			map.put(id, klass);
		} catch (InstantiationException ex) {
			GlieseLogger.LOGGER.error("Invalid message class", ex);
		} catch (IllegalAccessException ex) {
			GlieseLogger.LOGGER.error("Invalid message class", ex);
		}
	}

	private Class<? extends SSHMessage> getMessageClass(int id, String namespace)
		throws SSHException
	{
		Class<? extends SSHMessage> klass = null;
		Map<Integer, Class<? extends SSHMessage>> map
			= types.get(namespace);
		if (map != null) {
			klass = map.get(id);
		}
		if (klass == null && namespace != null) {
			return getMessageClass(id, null);
		} else if (klass == null) {
			throw new SSHException(String.format("Unsupported message type: %d", id));
		}
		return klass;
	}

	/**
	 * Reads a SSH packet and decodes the message.
	 *
	 * @param namespace  the message decoding namespace
	 * @return  the decoded mssage
	 * @throws IOException  if an error occurred while reading the stream
	 */
	private SSHMessage readPacket(String namespace)
		throws IOException, SSHException
	{
		synchronized (in) {
			in.initialize();
			int plen = Utils.decodeInt(in);
			int padlen = Utils.decodeByte(in) & 0xff;
			int msgType = Utils.decodeByte(in);
			Class<? extends SSHMessage> klass
				= getMessageClass(msgType, namespace);
			if (klass == null) {
				throw new IOException("Unsupported message type: " + msgType);
			}
			SSHMessage msg;
			try {
				msg = klass.newInstance();
				PayloadInputStream pin = new PayloadInputStream(in, plen - padlen - 2);
				msg.decode(pin);
				pin.flush();
			} catch (IllegalAccessException iae) {
				throw new SSHException("Unable to create message", iae);
			} catch (InstantiationException ie) {
				throw new SSHException("Unable to create message", ie);
			}
			Utils.decodeBytes(in, padlen);
			if (!in.checkMac()) {
				try {
					writeMessage(new DisconnectMessage(
						DisconnectMessage.MAC_ERROR,
						"Bad MAC on input", null));
				} catch (SSHException se) {
					// ignore exception
				}
				throw new SSHException("Bad MAC on input");
			}
			return msg;
		}
	}

	private  void writePacket(SSHMessage msg) throws IOException
	{
		synchronized (out) {
			out.initialize();
			byte[] msgEnc = msg.encode();
			byte[] encoding = new byte[msgEnc.length + 1];
			encoding[0] = (byte)msg.getID();
			System.arraycopy(msgEnc, 0, encoding, 1, msgEnc.length);
			int len = encoding.length + 9;
			int padlen = 4 + blockSizeCS - (len % blockSizeCS);
			Utils.encodeInt(out, encoding.length + padlen + 1);
			out.write(padlen);
			out.write(encoding);
			byte[] padding = new byte[padlen];
			rnd.nextBytes(padding);
			out.write(padding);
			out.writeMac();
			out.flush();
		}
	}

	/**
	 * Updates the Ciphers and Macs.
	 *
	 * @param ccs  the client to server cipher
	 * @param csc  the server to client cipher
	 * @param mcs  the client to server mac
	 * @param msc  the server to client mac
	 */
	public void newKeys(Cipher ccs, Cipher csc, Mac mcs, Mac msc)
	{
		synchronized (in) {
			blockSizeSC = csc.getBlockSize();
			in.updateCrypto(csc, msc);
		}
		synchronized (out) {
			blockSizeCS = ccs.getBlockSize();
			out.updateCrypto(ccs, mcs);
		}
	}

	public void writeMessage(SSHMessage msg)
		throws SSHException
	{
		try {
			writePacket(msg);
			GlieseLogger.LOGGER.debug("Sent message: " + msg);
		} catch (IOException ioe) {
			throw new SSHException("I/O exception on write", ioe);
		}
	}

	public SSHMessage readMessage(int... ids)
		throws SSHException
	{
		return readMessage(null, ids);
	}

	public SSHMessage readMessage(String namespace, int... ids)
		throws SSHException
	{
		SSHMessage m = readMessage(namespace);
		for (int id: ids) {
			if (id == m.getID()) {
				return m;
			}
		}
		throw new SSHException("Unexpected message type: " + m.getID());
	}

	public SSHMessage readMessage(String namespace)
		throws SSHException
	{
		try {
			SSHMessage m = readPacket(namespace);
			GlieseLogger.LOGGER.debug("Received message: " + m);
			return m;
		} catch (IOException ioe) {
			throw new SSHException("I/O error on read", ioe);
		}
	}

	public SSHMessage readMessage() throws SSHException
	{
		return readMessage((String)null);
	}
}
