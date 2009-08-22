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
 * This class computes SSH packet from {@code SSHMessage} instances.
 *
 * @author sirot
 */
public class PacketFactory
{
	private Map<Integer, Class<? extends SSHMessage>> types;
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
		this.types = new HashMap<Integer, Class<? extends SSHMessage>>();
		registerIncomingMessages();
	}
	
	private void registerIncomingMessages()
	{
		register(KexInitMessage.class);
		register(KexDHReplyMessage.class);
		register(NewKeysMessage.class);
		register(DebugMessage.class);
		register(DisconnectMessage.class);
		register(ServiceRequestMessage.class);
		register(ServiceAcceptMessage.class);
		register(UserAuthFailureMessage.class);
		register(UserAuthSuccessMessage.class);
		register(UserAuthBannerMessage.class);
		register(UserAuthPublicKeyOk.class);
	}

	/**
	 * register a new SSH message class.
	 *
	 * @param klass  the message class
	 */
	public <T extends SSHMessage> void register(Class<T> klass)
	{
		try {
			SSHMessage message = klass.newInstance();
			int id = message.getID();
			types.put(id, klass);
		} catch (InstantiationException ex) {
		} catch (IllegalAccessException ex) {
		}
	}

	/**
	 * Reads a SSH packet and decodes the message.
	 *
	 * @return  the decoded mssage
	 * @throws IOException  if an error occurred while reading the stream
	 */
	private synchronized SSHMessage readPacket()
		throws IOException, SSHException
	{
		in.initialize();
		int plen = Utils.decodeInt(in);
		int padlen = Utils.decodeByte(in) & 0xff;
		int msgType = Utils.decodeByte(in);
		Class<? extends SSHMessage> klass = types.get(msgType);
		if (klass == null) {
			throw new IOException("Unsupported message type: " + msgType);
		}
		SSHMessage msg;
		try {
			msg = klass.newInstance();
			msg.decode(new PayloadInputStream(in, plen - padlen - 2));
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
			}
			throw new SSHException("Bad MAC on input");
		}
		return msg;
	}

	private synchronized void writePacket(SSHMessage msg) throws IOException
	{
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

	public synchronized void newKeys(Cipher ccs, Cipher csc, Mac mcs, Mac msc)
	{
		blockSizeCS = ccs.getBlockSize();
		blockSizeSC = csc.getBlockSize();
		in.updateCrypto(csc, msc);
		out.updateCrypto(ccs, mcs);
	}

	public synchronized void writeMessage(SSHMessage msg)
		throws SSHException
	{
		try {
			writePacket(msg);
			GlieseLogger.LOGGER.debug("Sent message: " + msg);
		} catch (IOException ioe) {
			throw new SSHException("I/O exception on write", ioe);
		}
	}

	public synchronized SSHMessage readMessage(int... ids)
		throws SSHException
	{
		SSHMessage m = readMessage();
		for (int id: ids) {
			if (id == m.getID()) {
				return m;
			}
		}
		throw new SSHException("Unexpected message type: " + m.getID());
	}

	public synchronized SSHMessage readMessage() throws SSHException
	{
		try {
			SSHMessage m = readPacket();
			GlieseLogger.LOGGER.debug("Received message: " + m);
			return m;
		} catch (IOException ioe) {
			throw new SSHException("I/O error on read", ioe);
		}
	}
}
