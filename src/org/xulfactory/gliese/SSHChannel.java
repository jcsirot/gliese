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

import org.xulfactory.gliese.message.ChannelCloseMessage;
import org.xulfactory.gliese.message.ChannelDataMessage;
import org.xulfactory.gliese.message.ChannelFailureMessage;
import org.xulfactory.gliese.message.ChannelRequestMessage;
import org.xulfactory.gliese.message.ChannelRequestMessage.ChannelRequest;
import org.xulfactory.gliese.message.ChannelSuccessMessage;
import org.xulfactory.gliese.message.ChannelWindowsAdjustMessage;
import org.xulfactory.gliese.message.ExecChannelRequest;
import org.xulfactory.gliese.message.ExitStatusChannelRequest;
import org.xulfactory.gliese.message.SSHMessage;
import org.xulfactory.gliese.util.GlieseLogger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * A channel between the client and the remote peer.
 *
 * @author sirot
 */
public final class SSHChannel
{
	/** channel opening lock */
	final Object LOCK = new Object();
	private final int localId;
	private final int remoteId;
	private final ChannelManager manager;
	private final ChannelInputStream in;
	private final ChannelInputStream err;
	private final ChannelOutputStream out;
	private int exitStatus = -1;
	private boolean peerClose = false;
	private boolean closeSent = false;
	private long lSize, rSize;
	private long lAvailable, rAvailable;
	private final int rPacketMax;
	boolean lastReqSuccess = false;

	SSHChannel(int localId, int remoteId, long lSize, long rSize,
		int rPacketMax, ChannelManager manager)
	{
		this.localId = localId;
		this.remoteId = remoteId;
		this.manager = manager;
		this.lSize = lSize;
		this.lAvailable = lSize;
		this.rSize = rSize;
		this.rAvailable = rSize;
		this.rPacketMax = rPacketMax;
		this.in = new ChannelInputStream();
		this.err = new ChannelInputStream();
		this.out = new ChannelOutputStream();
	}

	/**
	 * Executes a command on the remote host;
	 *
	 * @param command  the command to execute.
	 *
	 * @throws SSHException
	 */
	public void execCommand(String command) throws SSHException
	{
		lastReqSuccess = false;
		ChannelRequestMessage msg = new ChannelRequestMessage();
		msg.setChannelId(remoteId);
		msg.setWantReply(true);
		ExecChannelRequest req = new ExecChannelRequest(command);
		msg.setRequest(req);
		manager.writeMessage(msg);
		synchronized (LOCK) {
			while (true) {
				try {
					LOCK.wait();
					break;
				} catch (InterruptedException ie) {
					// ignore
				}
			}
		}
		if (!lastReqSuccess) {
			throw new SSHException(
				"Remote peer rejected exec request");
		}
	}

	void handleRequest(ChannelRequest request, boolean wantReply)
	{
		boolean success = false;
		if ("exit-status".equals(request.getRequestType())) {
			exitStatus = ((ExitStatusChannelRequest)request).getStatus();
			success = true;
		} else if ("eow@openssh.com".equals(request.getRequestType())) {
			out.close();
		} else {
			GlieseLogger.LOGGER.warn("Unsupported channel request: "
				+ request.getRequestType());
		}
		if (wantReply) {
			SSHMessage msg;
			if (success) {
				msg = new ChannelSuccessMessage(remoteId);
			} else {
				msg = new ChannelFailureMessage(remoteId);
			}
			try {
				manager.writeMessage(msg);
			} catch (SSHException se) {
				GlieseLogger.LOGGER.error(se);
			}
		}
	}

	/**
	 * Retrieves the exit status.
	 *
	 * @return the exit status or -1 if no exit status has been send
	 */
	public int getExitStatus()
	{
		return exitStatus;
	}

	synchronized void peerClose() throws SSHException
	{
		// out.peerClose();
		peerClose = true;
		in.close();
		out.close();
		err.close();
		notifyAll();
	}

	/**
	 * Closes the channel an wait the peer close message if it has not
	 * been set.
	 *
	 * @throws SSHException
	 */
	public void close() throws SSHException
	{
		ChannelCloseMessage msg = new ChannelCloseMessage();
		msg.setChannelId(remoteId);
		manager.writeMessage(msg);
		in.close();
		out.close();
		err.close();
		if (peerClose) {
			return;
		}
		synchronized (this) {
			while (!peerClose) {
				try {
					wait();
				} catch (InterruptedException ie) {
					// ignore
				}
			}
		}
	}

	public synchronized boolean isClosed()
	{
		return peerClose && closeSent;
	}

	public InputStream getInputStream()
	{
		return in;
	}

	public InputStream getErrorStream()
	{
		return err;
	}

	public OutputStream getOutputStream()
	{
		return out;
	}

	void pushData(final byte[] data)
	{
		int len = checkLocalWindow(data.length);
		in.pushData(data, len);
		GlieseLogger.LOGGER.debug(String.format("read %d bytes on channel %d", len, localId));
	}

	void pushExtendedData(final byte[] data, int dataType)
	{
		int len = checkLocalWindow(data.length);
		if (dataType == 1) {
			err.pushData(data, len);
		} else {
			GlieseLogger.LOGGER.warn("Unsupported extended data type: " + dataType);
		}
	}

	/**
	 * Checks if the received data enters in the available window. Drops
	 * any extra data.
	 *
	 * @param len  the length of received data
	 * @param the length of data to be copied on the stream
	 */
	private synchronized int checkLocalWindow(int len)
	{
		long max = lAvailable;
		if (max < len) {
			GlieseLogger.LOGGER.warn(String.format(
				"Peer data length exceeds allowed windows " +
				"size. %d bytes dropped.", len - max));
			return (int)max;
		}
		return len;
	}

	private synchronized void adjustLocalWindow(int len)
	{
		/* double the window size when 75% has been consummed */
		long threshold = lSize >> 2;
		lAvailable -= len;
		if (lAvailable <= threshold) {
			ChannelWindowsAdjustMessage msg = new ChannelWindowsAdjustMessage(remoteId, lSize);
			try {
				manager.writeMessage(msg);
				lAvailable += lSize;
				lSize = lSize << 1;
			} catch (SSHException se) {
				GlieseLogger.LOGGER.error("Unable to send message: " + msg);
			}
		}
	}

	void adjustRemoteWindow(long len)
	{
		synchronized (out) {
			rSize += len;
			rAvailable += len;
			GlieseLogger.LOGGER.debug(String.format("Increase " +
				"remote window channel=%d, added bytes=%d",
				localId, len));
			out.notifyAll();
		}
	}

	void eof()
	{
		in.eof();
		err.eof();
		GlieseLogger.LOGGER.debug(String.format("EOF on channel %d", localId));
	}

	private class ChannelInputStream extends InputStream
	{
		private Pipe pipe;
		private boolean eof = false;
		private boolean closed = false;

		public ChannelInputStream()
		{
			pipe = new Pipe(0x4000);
		}

		private synchronized void pushData(byte[] data, int len)
		{
			if (eof) {
				/* Input is closed, drop new data */
				return;
			}
			pipe.write(data, 0, len);
		}

		synchronized void eof()
		{
			pipe.peerClose();
		}

		@Override
		public int read() throws IOException
		{
			int x = pipe.read();
			adjustLocalWindow(1);
			return x;
		}

		@Override
		public int read(byte[] buf) throws IOException
		{
			return read(buf, 0, buf.length);
		}

		@Override
		public int read(byte[] buf, int off, int len) throws IOException
		{
			int l = pipe.read(buf, off, len);
			adjustLocalWindow(l);
			return l;
		}

		@Override
		public int available() throws IOException
		{
			return pipe.available();
		}

		@Override
		public void close()
		{
			this.closed = true;
		}
	}

	private class ChannelOutputStream extends OutputStream
	{
		private boolean closed = false;

		@Override
		public void write(int b) throws IOException
		{
			write(new byte[] {(byte)b}, 0, 1);
		}

		@Override
		public void write(byte[] buf) throws IOException
		{
			write(buf, 0, buf.length);
		}

		@Override
		public synchronized void write(byte[] buf, int off, int len)
			throws IOException
		{
			while (len > 0) {
				if (closed) {
					throw new IOException("Channel is closed");
				}
				int l = Math.min((int)Math.min(len, rAvailable),
					rPacketMax);
				if (l == 0) {
					try {
						wait();
						continue;
					} catch (InterruptedException ex) {
					}
				}
				ChannelDataMessage msg = new ChannelDataMessage();
				msg.setChannelId(remoteId);
				msg.setData(buf, off, l);
				try {
					manager.writeMessage(msg);
				} catch (SSHException se) {
					throw new IOException(se);
				}
				rAvailable -= l;
				len -= l;
			}
		}

		public synchronized void close()
		{
			this.closed = true;
			notifyAll();
		}
	}
}
