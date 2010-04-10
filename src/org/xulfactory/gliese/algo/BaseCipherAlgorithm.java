/*
 *  Copyright 2009-2010 Jean-Christophe Sirot <sirot@xulfactory.org>.
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

package org.xulfactory.gliese.algo;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.xulfactory.gliese.CipherAlgorithm;

/**
 * Base implementation of {@code CipherAlgorithm}.
 *
 * @author sirot
 */
public class BaseCipherAlgorithm implements CipherAlgorithm
{
	private String name;
	private int keyLength;
	private int blockLength;
	private String algoName;
	private String keyName;

	/**
	 * Creates an {@code AlgorithmDescriptor}.
	 *
	 * @param name   the SSH standardized cipher name
	 * @param algoName   the JCA cipher algorithm name
	 * @param keyName   the JCA key name
	 * @param blockLength   the block length in bytes for block cipher
	 * @param keyLength   the key length in bytes
	 */
	public BaseCipherAlgorithm(String name, String algoName,
		String keyName, int blockLength, int keyLength)
	{
		this.name = name;
		this.keyLength = keyLength;
		this.blockLength = blockLength;
		this.algoName = algoName;
		this.keyName = keyName;
	}

	public int getBlockLength()
	{
		return blockLength;
	}

	public int getKeyLength()
	{
		return keyLength;
	}

	public String getName()
	{
		return name;
	}

	public Cipher getInstance(byte[] key, byte[] iv, int mode)
	{
		try {
			Cipher c = Cipher.getInstance(algoName);
			IvParameterSpec params = new IvParameterSpec(iv);
			Key skey = new SecretKeySpec(key, keyName);
			c.init(mode, skey, params);
			return c;
		} catch (InvalidAlgorithmParameterException iae) {
			throw new Error(iae);// FIXME
		} catch (NoSuchAlgorithmException nsae) {
			throw new Error(nsae);// FIXME
		} catch (InvalidKeyException ike) {
			throw new Error(ike);// FIXME
		} catch (NoSuchPaddingException nspe) {
			throw new Error(nspe);// FIXME
		}
	}
}
