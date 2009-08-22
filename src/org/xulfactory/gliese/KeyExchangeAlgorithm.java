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

import java.math.BigInteger;

/**
 * This interface of key exchange algorithm.
 *
 * @author Jean-Christophe Sirot
 */
public interface KeyExchangeAlgorithm extends SSHAlgorithm
{
	String getName();

	/**
	 * Executes the key exchange.
	 *
	 * @param transport   the transport
	 * @param pkf  the host public key factory
	 * @param verifier   the host public key verifier
	 * @throws SSHException
	 */
	void process(SSHTransport transport, SSHPublicKeyFactory pkf,
		HostKeyVerifier verifier)
		throws SSHException;

	BigInteger getSharedSecret();

	byte[] getExchangeHash();

	String getHashAlgorithm();
}
