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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import org.xulfactory.gliese.util.GlieseLogger;

/**
 * Default built-in configuration.
 *
 * @author sirot
 */
class DefaultAlgorithms implements KexInitAlgorithms
{
	private final List<KeyExchangeAlgorithm> KEX_ALGORITHMS;

	private final List<CipherAlgorithm> ENCRYPTION_ALGORITHMS;

	private final List<MacAlgorithm> MAC_ALGORITHMS;

	private final List<SSHPublicKeyFactory> KEY_ALGORITHMS;

	DefaultAlgorithms(AlgorithmRegistry registry)
	{
		this(registry, new Properties());
	}

	DefaultAlgorithms(AlgorithmRegistry registry, Properties props)
	{
		String tmp;
		tmp = props.getProperty("gliese.kex.kex", "diffie-hellman-group1-sha1, diffie-hellman-group14-sha1");
		String[] names = tmp.split("\\s*,\\s*");
		KEX_ALGORITHMS = new ArrayList<KeyExchangeAlgorithm>();
		setKex(names, registry);

		tmp = props.getProperty("gliese.kex.hostkey", "ssh-rsa, ssh-dss");
		names = tmp.split("\\s*,\\s*");
		KEY_ALGORITHMS = new ArrayList<SSHPublicKeyFactory>();
		setKeyFactories(names, registry);

		tmp = props.getProperty("gliese.kex.cipher", "aes128-cbc, 3des-cbc");
		names = tmp.split("\\s*,\\s*");
		ENCRYPTION_ALGORITHMS = new ArrayList<CipherAlgorithm>();
		setCiphers(names, registry);

		tmp = props.getProperty("gliese.kex.mac", "hmac-sha1, hmac-md5");
		names = tmp.split("\\s*,\\s*");
		MAC_ALGORITHMS = new ArrayList<MacAlgorithm>();
		setMacs(names, registry);
	}

	private void setKex(String[] names, AlgorithmRegistry registry)
	{
		for (String name: names) {
			KeyExchangeAlgorithm algo = registry.getKex(name);
			if (algo == null) {
				GlieseLogger.LOGGER.warn("Unknown key exchange algorithm: "+ name);
			} else {
				KEX_ALGORITHMS.add(algo);
			}
		}
	}

	private void setKeyFactories(String[] names, AlgorithmRegistry registry)
	{
		for (String name: names) {
			SSHPublicKeyFactory algo = registry.getKeyFactory(name);
			if (algo == null) {
				GlieseLogger.LOGGER.warn("Unknown server key algorithm: "+ name);
			} else {
				KEY_ALGORITHMS.add(algo);
			}
		}
	}

	private void setCiphers(String[] names, AlgorithmRegistry registry)
	{
		for (String name: names) {
			CipherAlgorithm algo = registry.getCipher(name);
			if (algo == null) {
				GlieseLogger.LOGGER.warn("Unknown cipher: "+ name);
			} else {
				ENCRYPTION_ALGORITHMS.add(algo);
			}
		}
	}

	private void setMacs(String[] names, AlgorithmRegistry registry)
	{
		for (String name: names) {
			MacAlgorithm algo = registry.getMac(name);
			if (algo == null) {
				GlieseLogger.LOGGER.warn("Unknown MAC: "+ name);
			} else {
				MAC_ALGORITHMS.add(algo);
			}
		}
	}

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
