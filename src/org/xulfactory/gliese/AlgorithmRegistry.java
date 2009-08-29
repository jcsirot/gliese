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

import java.util.HashMap;
import java.util.Map;

/**
 * Registry containing all supported algorithms
 *
 * @author sirot
 */
final class AlgorithmRegistry
{
	private Map<String, KeyExchangeAlgorithm> kexs
		= new HashMap<String, KeyExchangeAlgorithm>();
	private Map<String, SSHPublicKeyFactory> kfs
		= new HashMap<String, SSHPublicKeyFactory>();
	private Map<String, CipherAlgorithm> ciphers
		= new HashMap<String, CipherAlgorithm>();
	private Map<String, MacAlgorithm> macs
		= new HashMap<String, MacAlgorithm>();

	public AlgorithmRegistry()
	{
		register(DHGroupSHA1.group1());
		register(DHGroupSHA1.group14());
		register(new BaseCipherAlgorithm("aes128-cbc", "AES/CBC/NoPadding", "AES", 16, 16));
		register(new BaseCipherAlgorithm("3des-cbc", "DESede/CBC/NoPadding", "DESede", 8, 24));
		register(new BaseMacAlgorithm("hmac-sha1", "HmacSHA1", 20, 20));
		register(new BaseMacAlgorithm("hmac-md5", "HmacMD5", 16, 16));
		register(new SSHRSAPublicKey.SSHRSAPublicKeyFactory());
		register(new SSHDSSPublicKey.SSHDSSPublicKeyFactory());
	}

	void register(KeyExchangeAlgorithm kex)
	{
		kexs.put(kex.getName(), kex);
	}

	KeyExchangeAlgorithm getKex(String name)
	{
		return kexs.get(name);
	}

	void register(SSHPublicKeyFactory kf)
	{
		kfs.put(kf.getName(), kf);
	}

	SSHPublicKeyFactory getKeyFactory(String name)
	{
		return kfs.get(name);
	}

	void register(CipherAlgorithm cipher)
	{
		ciphers.put(cipher.getName(), cipher);
	}

	CipherAlgorithm getCipher(String name)
	{
		return ciphers.get(name);
	}

	void register(MacAlgorithm mac)
	{
		macs.put(mac.getName(), mac);
	}

	MacAlgorithm getMac(String name)
	{
		return macs.get(name);
	}
}
