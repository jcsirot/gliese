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
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NullCipher;

/**
 *
 * @author sirot
 */
class SSHInputStream extends InputStream
{
	private InputStream sub;
	private Cipher cipher = new NullCipher();
	private Mac mac;
	private long seq = 0;
	private byte[] buffer;
	private int bs;
	private int index;
	private int updated = 0;

	public SSHInputStream(InputStream in, Cipher cipher, Mac mac)
	{
		this.sub = in;
		updateCrypto(cipher, mac);
	}

	public SSHInputStream(InputStream in)
	{
		this(in, null, null);
	}
	
	private synchronized int getNextBlock() throws IOException
	{
		byte[] input = new byte[bs];
		/* try reading enough data to decrypt the next block */
		int len = sub.read(input, 0, bs - updated);
		if (len == -1) {
			return -1;
		}
		buffer = cipher.update(input);
		updated += len;
		if (buffer == null) {
			index = -1;
			return 0;
		} else {
			index = 0;
			updated = 0;
			return buffer.length;
		}
	}

	synchronized void updateCrypto(Cipher cipher, Mac mac)
	{
		if (cipher == null) {
			this.cipher = new NullCipher();
			this.bs = 8;
		} else {
			this.cipher = cipher;
			this.bs = cipher.getBlockSize();
		}
		this.mac = mac;
		this.index = bs;
	}

	public void initialize()
	{
		if (mac != null) {
			mac.reset();
			mac.update(Utils.encodeInt(seq));
		}
		seq = (seq + 1) % 0xffffffffL;
	}

	public boolean checkMac() throws IOException
	{
		if (mac == null) {
			return true;
		}
		int len = mac.getMacLength();
		byte[] tmp = new byte[len];
		int r = len;
		do {
			int l = sub.read(tmp);
			if (l == -1) {
				throw new IOException("Trunccated input");
			}
			r = r - l;
		} while (r > 0);
		byte[] code = mac.doFinal();
		return Arrays.equals(tmp, code);
	}

	@Override
	public int read() throws IOException
	{
		if (index >= bs) {
			int len;
			do {
				len = getNextBlock();
			} while (len == 0);
			if (len == -1) {
				return -1;
			}
		}
		int b = buffer[index++];
		if (b >= 0 && mac != null) {
			mac.update((byte)b);
		}
		return b;
	}

	@Override
	public int read(byte[] tmp) throws IOException
	{
		return read(tmp, 0, tmp.length);
	}

	@Override
	public int read(byte[] tmp, int off, int len) throws IOException
	{
		int copied = 0;
		do {
			if (index >= bs) {
				int l = getNextBlock();
				if (l <= 0) {
					return l;
				}
			}
			int av = bs - index;
			int rem = len - copied;
			int l = av <= rem ? av : rem;
			System.arraycopy(buffer, index, tmp, off + copied, l);
			index += l;
			copied += l;
		} while (copied < len);
		if (mac != null) {
			mac.update(tmp, off, copied);
		}
		return copied;
	}
}
