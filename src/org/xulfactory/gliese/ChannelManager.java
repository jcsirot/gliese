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

package org.xulfactory.gliese;

import org.xulfactory.gliese.message.ChannelDataMessage;
import org.xulfactory.gliese.message.ChannelOpenConfirmationMessage;
import org.xulfactory.gliese.message.ChannelOpenMessage;
import org.xulfactory.gliese.message.ChannelRequestMessage;
import org.xulfactory.gliese.message.ChannelWindowsAdjustMessage;
import org.xulfactory.gliese.message.ChannelEOFMessage;
import org.xulfactory.gliese.message.SSHMessage;
import org.xulfactory.gliese.message.ChannelCloseMessage;
import org.xulfactory.gliese.message.ChannelSuccessMessage;
import org.xulfactory.gliese.message.ChannelFailureMessage;
import org.xulfactory.gliese.message.ChannelExtendedDataMessage;
import org.xulfactory.gliese.util.GlieseLogger;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

/**
 *
 * @author sirot
 */
class ChannelManager
{
// 	private int DEFAULT_WIN_INIT_SIZE = 0x4000;
// 	private int DEFAULT_PACKET_MAX_SIZE = 0x1000;
 	private int DEFAULT_WIN_INIT_SIZE = 0x400;
 	private int DEFAULT_PACKET_MAX_SIZE = 0x400;

	private SSHTransport transport;
	private Map<Integer, SSHChannel> locals;
	private Map<Integer, SSHChannel> remotes;
	private int chanId = 1;
	private Thread readerThread;
	private BlockingQueue<SSHMessage> queue;

	ChannelManager(SSHTransport transport)
	{
		this.transport = transport;
		this.locals = new HashMap<Integer, SSHChannel>();
		this.remotes = new HashMap<Integer, SSHChannel>();
		queue = new ArrayBlockingQueue<SSHMessage>(16);
	}

	private synchronized void start()
	{
		if (readerThread != null) {
			return;
		} else {
			readerThread = new Thread(new Runnable() {
				public void run()
				{
					while (true) {
						try {
							channelLoop();
						} catch (SSHException se) {
							break;
						}
					}
				}
			}, "ChannelManager");
			readerThread.start();
		}
	}

	public void channelLoop() throws SSHException
	{
		SSHChannel chann = null;
		SSHMessage msg = transport.readMessage();
		switch (msg.getID()) {
		case ChannelSuccessMessage.ID:
			ChannelSuccessMessage m5 = (ChannelSuccessMessage)msg;
			chann = locals.get(m5.getChannelId());
			synchronized (chann.LOCK) {
				chann.lastReqSuccess = true;
				chann.LOCK.notify();
			}
			break;
		case ChannelFailureMessage.ID:
			ChannelFailureMessage m6 = (ChannelFailureMessage)msg;
			chann = locals.get(m6.getChannelId());
			synchronized (chann.LOCK) {
				chann.lastReqSuccess = false;
				chann.LOCK.notify();
			}
			break;
		case ChannelRequestMessage.ID:
			ChannelRequestMessage m0 = (ChannelRequestMessage)msg;
			chann = locals.get(m0.getChannelId());
			chann.handleRequest(m0.getRequest(), m0.getWantReply());
			break;
		case ChannelWindowsAdjustMessage.ID:
			break; // FIXME
		case ChannelEOFMessage.ID:
			ChannelEOFMessage m2 = (ChannelEOFMessage)msg;
			chann = locals.get(m2.getChannelId());
			chann.eof();
			break;
		case ChannelDataMessage.ID:
			ChannelDataMessage m1 = (ChannelDataMessage)msg;
			chann = locals.get(m1.getChannelId());
			chann.pushData(m1.getData());
			break;
		case ChannelExtendedDataMessage.ID:
			ChannelExtendedDataMessage m3 =
				(ChannelExtendedDataMessage)msg;
			chann = locals.get(m3.getChannelId());
			chann.pushExtendedData(m3.getData(), m3.getDataType());
			break;
		case ChannelOpenConfirmationMessage.ID:
			try {
				queue.put(msg);
			} catch (InterruptedException ex) {
				ex.printStackTrace();
			}
			break;
		case ChannelCloseMessage.ID:
			ChannelCloseMessage m4 = (ChannelCloseMessage)msg;
			chann = locals.get(m4.getChannelId());
			chann.peerClose();
			break;
		default:
			GlieseLogger.LOGGER.error(String.format(
				"Unexpected message type: %d", msg.getID()));
		}
	}

	public SSHChannel openSession() throws SSHException
	{
		start();
		ChannelOpenMessage msg = new ChannelOpenMessage();
		msg.setChannelId(chanId++);
		msg.setChannelType("session");
		msg.setInitialWindowSize(DEFAULT_WIN_INIT_SIZE);
		msg.setMaxPacketSize(DEFAULT_PACKET_MAX_SIZE);
		transport.writeMessage(msg);
		ChannelOpenConfirmationMessage conf = null;
		try {
			conf = (ChannelOpenConfirmationMessage)queue.take();
		} catch (InterruptedException ie) {
			ie.printStackTrace();
			throw new SSHException("Unexpected error", ie);
		}
		SSHChannel chann = new SSHChannel(conf.getRecipientChannelId(),
			conf.getSenderChannelId(), DEFAULT_WIN_INIT_SIZE, this);
		locals.put(conf.getRecipientChannelId(), chann);
		remotes.put(conf.getSenderChannelId(), chann);
		return chann;
	}

	/**
	 * Sends a message to the server.
	 *
	 * @param msg  the message
	 * @throws SSHException if an error occurred
	 */
	void writeMessage(SSHMessage msg) throws SSHException
	{
		transport.writeMessage(msg);
	}
}
