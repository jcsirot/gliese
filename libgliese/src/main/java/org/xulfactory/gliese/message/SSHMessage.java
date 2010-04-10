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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Common mother class for all SSH messages. A message in wrapped into a
 * packet by the {@link PacketFactory}. A SSH packet is the elementary protocol
 * element exchanged by the client and the server.
 *
 * @author Jean-Christophe Sirot
 */
public abstract class SSHMessage
{
	protected int id;
	protected byte[] payload;

	/**
	 * Create a new {@code SSHMessage} instance.
	 *
	 * @param id  the message ID
	 */
	protected SSHMessage(int id)
	{
		this.id = id;
	}

	/**
	 * Retrieves the message ID number.
	 *
	 * @return the message ID
	 */
	public int getID()
	{
		return id;
	}

	final void decode(byte[] payload)
	{
		try {
			decode(new ByteArrayInputStream(payload));
		} catch (IOException ioe) {
			/* Does not happen */
			throw new Error(ioe);
		}
	}

	/**
	 * Decodes the message payload from the stream. <strong>Do not read the
	 * message ID number</strong> since it has been done previously.
	 *
	 * @param in  the input stream
	 * @throws IOException  if an I/O error occurred while reading
	 *         the message
	 */
	protected abstract void decode(InputStream in) throws IOException;

	final byte[] encode()
	{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			encode(out);
		} catch (IOException ioe) {
			/* Does not happen */
			throw new Error(ioe);
		}
		return out.toByteArray();
	}

	/**
	 * Encodes the message payload into the stream. <strong>Do not 
	 * write the message ID number</strong>.
	 *
	 * @param out  the output stream
	 * @throws IOException  if an I/O error occurred while
	 *         writing the message
	 */
	protected abstract void encode(OutputStream out) throws IOException;
}
