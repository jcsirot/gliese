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

import java.io.Console;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author sirot
 */
public class ConsoleHostKeyVerifier implements HostKeyVerifier
{
	/** @see HostKeyVerifier */
	public boolean isTrusted(SSHTransport transport, String name, byte[] key)
		throws SSHException
	{
		byte[] fp = null;
		try {
			MessageDigest dg = MessageDigest.getInstance("MD5");
			fp = dg.digest(key);
		} catch (NoSuchAlgorithmException nsae) {
			// ignore;
		}
		System.out.println(String.format("Key fingerprint for %s(%s): %s",
			transport.getPeer().getHostName(),
			transport.getPeer().getHostAddress(),
			toString(fp)));
		Console console = System.console();
		String rsp = console.readLine("Trust key (yes/no)? ");
		return rsp != null && rsp.trim().equalsIgnoreCase("yes");
	}

	private static String toString(byte[] a)
	{
		if (a == null || a.length == 0) {
			return "";
		}
		StringBuilder sb = new StringBuilder();
		sb.append(String.format("%02x", a[0]));
		for (int i = 1; i < a.length; i++) {
			sb.append(String.format(":%02x", a[i]));
		}
		return sb.toString();
	}
}
