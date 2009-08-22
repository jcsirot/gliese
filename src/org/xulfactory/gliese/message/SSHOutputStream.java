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
import java.io.OutputStream;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NullCipher;

/**
 *
 * @author sirot
 */
class SSHOutputStream extends OutputStream
{
	private OutputStream sub;
	/** Sequence number */
	private long seq = 0;
	private Cipher cipher;
	private Mac mac;

	SSHOutputStream(OutputStream out, Cipher cipher, Mac mac)
	{
		this.sub = out;
		updateCrypto(cipher, mac);
	}

	SSHOutputStream(OutputStream out)
	{
		this(out, null, null);
	}

	synchronized void updateCrypto(Cipher cipher, Mac mac)
	{
		if (cipher != null) {
			this.cipher = cipher;
		} else {
			this.cipher = new NullCipher();
		}
		this.mac = mac;
	}

	public void initialize()
	{
		if (mac != null) {
			mac.reset();
			mac.update(Utils.encodeInt(seq));
		}
		seq = (seq + 1) % 0xffffffffL;
	}

	public void writeMac() throws IOException
	{
		if (mac == null) {
			return;
		}
		byte[] code = mac.doFinal();
		sub.write(code);
	}

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
	public void write(byte[] buf, int off, int len) throws IOException
	{
		if (mac != null) {
			mac.update(buf, off, len);
		}
		byte[] data = cipher.update(buf, off, len);
		if (data != null) {
			sub.write(data);
		}
	}

	@Override
	public void flush() throws IOException
	{
		sub.flush();
	}
}
