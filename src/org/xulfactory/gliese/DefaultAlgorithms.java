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

import java.util.Arrays;
import java.util.List;
import org.xulfactory.gliese.CipherAlgorithm.BaseCipherAlgorithm;
import org.xulfactory.gliese.MacAlgorithm.BaseMacHandler;

/**
 * Default built-in configuration.
 *
 * @author sirot
 */
class DefaultAlgorithms implements SSHAlgorithms
{
	private static final List<KeyExchangeAlgorithm> KEX_ALGORITHMS =
		Arrays.asList(new KeyExchangeAlgorithm[] {
			DHGroupSHA1.group1(),
			DHGroupSHA1.group14()
		}
	);

	private static final List<CipherAlgorithm> ENCRYPTION_ALGORITHMS =
		Arrays.asList(new CipherAlgorithm[] {
			new BaseCipherAlgorithm("aes128-cbc", "AES/CBC/NoPadding", "AES", 16, 16),
			new BaseCipherAlgorithm("3des-cbc", "DESede/CBC/NoPadding", "DESede", 24, 8),
		}
	);

	private static final List<MacAlgorithm> MAC_ALGORITHMS =
		Arrays.asList(new MacAlgorithm[]{
			new BaseMacHandler("hmac-sha1", "HmacSHA1", 20, 20),
			new BaseMacHandler("hmac-md5", "HmacMD5", 16, 16),
		}
	);

	private static final List<SSHPublicKeyFactory> KEY_ALGORITHMS =
		Arrays.asList(new SSHPublicKeyFactory [] {
			new SSHRSAPublicKey.SSHRSAPublicKeyFactory(),
			new SSHDSSPublicKey.SSHDSSPublicKeyFactory(),
		}
	);

	public List<KeyExchangeAlgorithm> getKexAlgorithms()
	{
		return KEX_ALGORITHMS;
	}
	public List<CipherAlgorithm> getEncryptionAlgorithms()
	{
		return ENCRYPTION_ALGORITHMS;
	}

	public List<MacAlgorithm> getMacAlgorithms()
	{
		return MAC_ALGORITHMS;
	}

	public List<SSHPublicKeyFactory> getServerHostKeyAlgorithms()
	{
		return KEY_ALGORITHMS;
	}
}
