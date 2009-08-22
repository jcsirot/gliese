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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * This {@code InputStream} reads up to the packet payload bytes
 * on the underlying stream.
 * 
 * @author Jean-Christophe Sirot
 */
public class PayloadInputStream extends FilterInputStream
{
	private int rem;
	private final int maxlen;

	public PayloadInputStream(InputStream is, int maxlen)
	{
		super(is);
		this.maxlen = maxlen;
		this.rem = maxlen;
	}

	/** @see InputStream */
	public int read() throws IOException
	{
		if (rem <= 0) {
			return -1;
		} else {
			rem--;
			return super.read();
		}
	}

	public int read(byte[] buf, int off, int len)
		throws IOException
	{
		if (rem <= 0) {
			return -1;
		} else {
			if (len > rem) {
				len = rem;
			}
			int l = super.read(buf, off, len);
			rem -= l;
			return l;
		}
	}

	public int getSize()
	{
		return maxlen;
	}
}
