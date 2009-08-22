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
import org.xulfactory.gliese.SSHTimeoutException;
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
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
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
	private final BlockingQueue<SSHMessage> outQueue;
	private final BlockingQueue<SSHMessage> inQueue;
	private boolean isClosed;
	private boolean inCrytoUpdated = true;
	private boolean outCrytoUpdated = true;
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
		//this.oin = new BufferedInputStream(in);
		this.oin = in;
		this.inQueue = new ArrayBlockingQueue<SSHMessage>(1024);
		this.outQueue = new ArrayBlockingQueue<SSHMessage>(1024);
		this.in = new SSHInputStream(oin);
		//this.oout = new BufferedOutputStream(out);
		this.oout = out;
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
	 * Starts the input and output threads.
	 */
	public void start()
	{
		(new InputThread()).start();
		(new OutputThread()).start();
	}

	/**
	 * Reads a SSH packet and decodes the message.
	 *
	 * @return  the decoded mssage
	 * @throws IOException  if an error occurred while reading the stream
	 */
	private SSHMessage readPacket() throws IOException, SSHException
	{
		in.intialize();
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
		} catch (Exception e) {
			e.printStackTrace();
			throw new Error(e);
		}
		Utils.decodeBytes(in, padlen);
		if (!in.checkMac()) {
			try {
				writeMessage(new DisconnectMessage(
					DisconnectMessage.MAC_ERROR,
					"Bad MAC on input", null));
			} catch (SSHTimeoutException te) {
			}
			GlieseLogger.LOGGER.error("Bad MAC on input");
			throw new SSHException("Bad MAC on input");
		}
		return msg;
	}

	private void writePacket(SSHMessage msg) throws IOException
	{
		out.intialize();
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

	public void newKeys(Cipher ccs, Cipher csc, Mac mcs, Mac msc)
	{
		blockSizeCS = ccs.getBlockSize();
		blockSizeSC = csc.getBlockSize();
		synchronized(in) {
			in.updateCrypto(csc, msc);
			inCrytoUpdated = true;
			in.notifyAll();
		}
		synchronized(out) {
			out.updateCrypto(ccs, mcs);
			outCrytoUpdated = true;
			out.notifyAll();
		}
	}

	public void writeMessage(SSHMessage msg) 
		throws SSHException, SSHTimeoutException
	{
		try {
			if (!outQueue.offer(msg, 5, TimeUnit.SECONDS)) {
				throw new SSHTimeoutException("Timeout");
			}
		} catch (InterruptedException ex) {
			throw new SSHTimeoutException("Interrupted");
		}
	}

	public SSHMessage readMessage(int... ids) 
		throws SSHException, SSHTimeoutException
	{
		SSHMessage m = readMessage();
		for (int id: ids) {
			if (id == m.getID()) {
				return m;
			}
		}
		GlieseLogger.LOGGER.error("Unexpected message type: " + m.getID());
		throw new SSHException("Unexpected message type: " + m.getID());
	}

	public SSHMessage readMessage() throws SSHException, SSHTimeoutException
	{
		try {
			SSHMessage m = inQueue.poll(500, TimeUnit.SECONDS);
			if (m == null) {
				throw new SSHTimeoutException("Timeout on read");
			}
			return m;
		} catch (InterruptedException ex) {
			throw new SSHTimeoutException("Interrupted");
		}
	}

	private class InputThread extends Thread
	{
		public InputThread()
		{
			super("Input");
		}

		@Override
		public void run()
		{
			while (!isClosed) {
				try {
					run0();
				} catch (IOException ioe) {
					handleError(ioe);
				} catch (SSHException se) {
					handleError(se);
				}
			}
		}

		private void handleError(Throwable t)
		{
			try {
				isClosed = true;
				oin.close();
				oout.close();
				GlieseLogger.LOGGER.error("I/O error on read", t);
			} catch (IOException ioe) {
				// ignore
			}
		}

		private void run0() throws IOException, SSHException
		{
			SSHMessage m = readPacket();
			GlieseLogger.LOGGER.debug("Received message: " + m);
			try {
				inQueue.put(m);
			} catch (InterruptedException ex) {
				// When it occurs, we are in serious trouble.
			}
			if (m.getID() == NewKeysMessage.ID) {
				/* Wait for crypto update */
				synchronized(in) {
					inCrytoUpdated = false;
					while (!inCrytoUpdated) {
						try {
							in.wait();
						} catch (InterruptedException ex) {
						}
					}
				}
			}
		}
	}

	private class OutputThread extends Thread
	{
		public OutputThread()
		{
			super("Output");
		}

		@Override
		public void run()
		{
			while (!isClosed) {
				try {
					run0();
				} catch (IOException ioe) {
					ioe.printStackTrace();
					isClosed = true;
				}
			}
		}

		private void run0() throws IOException
		{
			SSHMessage m = null;
			while (true) {
				try {
					m = outQueue.poll(100, TimeUnit.MILLISECONDS);
					if (m != null) {
						break;
					}
					if (isClosed) {
						return;
					}
				} catch (InterruptedException ex) {
					// ignore
				}
			}
			writePacket(m);
			GlieseLogger.LOGGER.debug("Sent message: " + m);
			if (m.getID() == NewKeysMessage.ID) {
				synchronized(out) {
					outCrytoUpdated = false;
					while (!outCrytoUpdated) {
						try {
							out.wait();
						} catch (InterruptedException ex) {
						}
					}
				}
			}
		}
	}
}
