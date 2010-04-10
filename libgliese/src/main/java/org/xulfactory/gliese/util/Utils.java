/*
 *  Copyright 2009 sirot.
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

package org.xulfactory.gliese.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

/**
 * Provides utility methods to encode and decode data structure according
 * to the RFC-4251 specification.
 *
 * @author sirot
 */
public final class Utils
{
	private Utils() { }

	/**
	 * Decodes a single byte
	 *
	 * @param in   the input stream
	 * @return   the decoded byte
	 * @throws IOException   on IO error
	 */
	public static byte decodeByte(InputStream in) throws IOException
	{
		return decodeBytes(in, 1)[0];
	}

	public static byte[] decodeBytes(InputStream in) throws IOException
	{
		int len = decodeInt(in);
		return decodeBytes(in, len);
	}

	/**
	 * Decodes a byte array
	 *
	 * @param in   the input stream
	 * @param len  the array length
	 * @return   the decoded bytes
	 * @throws IOException  on IO error
	 */
	public static byte[] decodeBytes(InputStream in, int len) throws IOException
	{
		byte[] buf = new byte[len];
		if (len == 0) {
			return buf;
		}
		int r = len;
		for (;;) {
			int l = in.read(buf, len - r, r);
			if (l == -1) {
				throw new IOException("Truncated input");
			}
			r = r - l;
			if (r <= 0) {
				return buf;
			}
		}
	}

	/**
	 * Decodes a String encoded with US-ASCII encoding.
	 *
	 * @param in   the input stream
	 * @return  the decoded String
	 * @throws IOException  on IO error
	 */
	public static String decodeString(InputStream in) throws IOException
	{
		return new String(decodeBytes(in), "ASCII");
	}

	public static String decodeStringUTF8(InputStream in) throws IOException
	{
		return new String(decodeBytes(in), "UTF-8");
	}

	public static int decodeInt(InputStream in) throws IOException
	{
		byte[] tmp = decodeBytes(in, 4);
		int value =
				((tmp[0] << 24) & 0xff000000) |
				((tmp[1] << 16) & 0xff0000) |
				((tmp[2] << 8) & 0xff00) |
				(tmp[3] & 0xff);
		return value;
	}

	/**
	 * Decodes a list of names.
	 *
	 * @param in  the input stream
	 * @return  the decoded name list
	 *
	 * @throws IOException
	 */
	public static String[] decodeNameList(InputStream in) throws IOException
	{
		int len = decodeInt(in);
		byte[] tmp = decodeBytes(in, len);
		String str = new String(tmp, "ASCII");
		String[] nameList = str.split(",");
		return nameList;
	}

	/**
	 * Decodes a boolean value
	 *
	 * @param in   the input stream
	 * @return  the decoded boolean
	 * @throws IOException
	 */
	public static boolean decodeBoolean(InputStream in) throws IOException
	{
		return decodeByte(in) != 0;
	}

	public static BigInteger decodeBigInt(InputStream in) throws IOException
	{
		byte[] buf = decodeBytes(in);
		return new BigInteger(buf);
	}

	public static byte[] encodeBytes(byte[] data)
	{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			encodeInt(out, data.length);
			out.write(data);
		} catch (IOException ioe) {
			throw new Error(ioe);
		}
		return out.toByteArray();
	}

	public static void encodeBytes(OutputStream out, byte[] data)
		throws IOException
	{
		encodeInt(out, data.length);
		out.write(data);
	}

	public static void encodeStringUTF8(OutputStream out, String str)
		throws IOException
	{
		encodeBytes(out, str.getBytes("UTF-8"));
	}

	public static void encodeString(OutputStream out, String str)
		throws IOException
	{
		encodeBytes(out, str.getBytes("ASCII"));
	}

	public static byte[] encodeInt(long value)
	{
		byte[] tmp = new byte[4];
		tmp[0] = (byte)((value >>> 24) & 0xff);
		tmp[1] = (byte)((value >>> 16) & 0xff);
		tmp[2] = (byte)((value >>> 8) & 0xff);
		tmp[3] = (byte)(value & 0xff);
		return tmp;
	}

	public static void encodeInt(OutputStream out, long value)
			throws IOException
	{
		byte[] tmp = new byte[4];
		tmp[0] = (byte)((value >>> 24) & 0xff);
		tmp[1] = (byte)((value >>> 16) & 0xff);
		tmp[2] = (byte)((value >>> 8) & 0xff);
		tmp[3] = (byte)(value & 0xff);
		out.write(tmp);
	}

	public static void encodeNameList(OutputStream out, String[] nameList)
			throws IOException
	{
		if (nameList.length == 0) {
			out.write(new byte[] {0, 0, 0, 0});
		} else {
			StringBuilder sb = new StringBuilder();
			sb.append(nameList[0]);
			for (int i = 1; i < nameList.length; i++) {
				sb.append(",").append(nameList[i]);
			}
			byte[] encoding = sb.toString().getBytes("ASCII");
			encodeInt(out, encoding.length);
			out.write(encoding);
		}
	}

	public static void encodeBoolean(OutputStream out, boolean b)
			throws IOException
	{
		out.write(b ? 1 : 0);
	}

	public static void encodeBigInt(OutputStream out, BigInteger x)
			throws IOException
	{
		byte[] value = x.toByteArray();
		encodeInt(out, value.length);
		out.write(value);
	}

	public static byte[] encodeBigInt(BigInteger x)
	{
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			encodeBigInt(out, x);
			return out.toByteArray();
		} catch (IOException ioe) {
			/* Does not happen */
			throw new Error(ioe);
		}
	}
}
