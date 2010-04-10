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

import org.xulfactory.gliese.util.GlieseLogger;

/**
 * A pipe is a circular buffer where two threads can read and write data. When
 * the buffer is empty the call read methods blocks. When write methods are
 * called the internal buffer size is adjusted when necessary therefore the
 * call does not block.
 *
 * @author sirot
 */
class Pipe
{
	private byte[] buffer;

	/**
	 * The index of the position in the circular buffer where the
	 * next data byte will be written. The buffer is empty if
	 * <code>in &lt; 0</code>. The buffer is full if <code>in == out</code>.
	 */
	private int in;

	/**
	 * The index of the position in the circular buffer from where
	 * the next byte will be returned.
	 */
	private int out;

	private boolean peerClosed;

	Pipe(int initSize)
	{
		buffer = new byte[initSize];
		in = -1;
		out = 0;
	}

	private synchronized int getFreeSpace()
	{
		while (in == out) {
			try {
				wait();
			} catch (InterruptedException ie) {
				// ignore
			}
		}
		int len = buffer.length;
		if (in < 0)
			return len;
		int slen = in - out;
		if (slen < 0)
			slen += len;
		return slen;
	}

	synchronized void write(int v)
	{
		write(new byte[] { (byte)v }, 0, 1);
	}

	synchronized void write(byte[] buf)
	{
		write(buf, 0, buf.length);
	}

	synchronized void write(byte[] buf, int off, int len)
	{
		while (len > free()) {
			increase(buffer.length);
		}
		int blen = buffer.length;
		while (len > 0) {
			int clen = Math.min(getFreeSpace(), len);
			if (in < 0) {
				System.arraycopy(buf, off, buffer, 0, clen);
				in = clen;
				out = 0;
				notifyAll();
			} else {
				int rlen = blen - in;
				if (rlen <= clen) {
					System.arraycopy(buf, off,
						buffer, in, rlen);
					System.arraycopy(buf, off + rlen,
						buffer, 0, clen - rlen);
					in = clen - rlen;
				} else {
					System.arraycopy(buf, off,
						buffer, in, clen);
					in += clen;
				}
			}
			off += clen;
			len -= clen;
		}
	}

	synchronized int read()
	{
		while (in < 0) {
			if (isClosed())
				return -1;
			try {
				wait();
			} catch (InterruptedException ie) {
				// ignore
			}
		}
		if (in == out)
			notifyAll();
		int v = buffer[out ++] & 0xFF;
		if (out == buffer.length)
			out = 0;
		if (in == out)
			in = -1;
		return v;
	}

	synchronized int read(byte[] buf)
	{
		return read(buf, 0, buf.length);
	}

	synchronized int read(byte[] buf, int off, int len)
	{
		if (len < 0 || off < 0 || len > (buf.length - off))
			throw new IndexOutOfBoundsException();
		if (len == 0)
			return 0;
		/*
		 * We get the first byte. This blocks if there is no
		 * buffered data. Then we return that byte, and as
		 * many buffered bytes as we also have at that point
		 * in the buffer. Thus, we block no more than strictly
		 * necessary.
		 *
		 * The call to read() also performs the appropriate
		 * notification if the buffer was full prior to this call.
		 */
		int v = read();
		if (v < 0)
			return -1;
		buf[off ++] = (byte)v;
		if (-- len == 0 || in < 0)
			return 1;

		/*
		 * We have read a byte (so the buffer is not full anymore),
		 * we want more, and the buffer is not empty (this was
		 * explicitely filtered out).
		 */
		if (in <= out) {
			int blen = buffer.length;
			int clen = Math.min(len, in + blen - out);
			int rlen = blen - out;
			int elen = clen - rlen;
			if (elen < 0) {
				System.arraycopy(buffer, out, buf, off, clen);
				out += clen;
			} else {
				System.arraycopy(buffer, out, buf, off, rlen);
				System.arraycopy(buffer, 0,
					buf, off + rlen, elen);
				out = elen;
				if (in == out)
					in = -1;
			}
			return clen + 1;
		} else {
			int clen = Math.min(len, in - out);
			System.arraycopy(buffer, out, buf, off, clen);
			out += clen;
			if (in == out)
				in = -1;
			return clen + 1;
		}
	}

	synchronized int getBufferSize()
	{
		return buffer.length;
	}

	synchronized int free()
	{
		return buffer.length - available();
	}

	synchronized int available()
	{
		if (in < 0)
			return 0;
		int len = buffer.length;
		if (in < out) {
			return len - (out - in);
		} else if (in == out) {
			return len;
		} else {
			return in - out;
		}
	}

	/**
	 * Increases the buffer size of the given amount.
	 */
	synchronized void increase(int size)
	{
		byte[] nbuffer = new byte[buffer.length + size];
		if (in < 0) {
			buffer = nbuffer;
		} else if (in > out) {
			System.arraycopy(buffer, out, nbuffer, 0, in - out);
			out = 0;
			in = in - out;
			buffer = nbuffer;
		} else if (in <= out) {
			int len = buffer.length;
			System.arraycopy(buffer, out, nbuffer, 0, len - out);
			System.arraycopy(buffer, 0, nbuffer, len - out, in);
			out = 0;
			in = len - out + in;
			buffer = nbuffer;
		}
		GlieseLogger.LOGGER.debug(String.format("Old buffer size: %d, new buffer size: %d", nbuffer.length - size, nbuffer.length));
	}

	synchronized void peerClose()
	{
		this.peerClosed = true;
		notifyAll();
	}

	/**
	 * The pipe is considered closed when {@link  #peerClose()} has been
	 * called and the buffer has been emptied.
	 *
	 * @return {@code true} if the pipe is closed and all data has been 
	 *         read, {@code false} otherwise
	 */
	synchronized boolean isClosed()
	{
		return peerClosed && in < 0;
	}
}
