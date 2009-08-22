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

/**
 *
 * @author sirot
 */
public interface HostKeyVerifier
{
	/**
	 * Verifies whether the host public key is trustworthy.
	 *
	 * @param transport   the SSH transport layer
	 * @param name  public key algorithm name
	 * @param key  the encoded host key
	 * @return {@code true} if the key is trustworthy, {@code false}
	 *         otherwise
	 * @throws SSHException on error
	 */
	boolean isTrusted(SSHTransport transport, String name, byte[] key)
		throws SSHException;
}
