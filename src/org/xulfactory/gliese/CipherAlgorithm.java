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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author sirot
 */
public abstract class CipherAlgorithm implements SSHAlgorithm
{
	private String name;
	private int keyLength;
	private int blockLength;

	/**
	 * Creates an {@code AlgorithmDescriptor}.
	 *
	 * @param name   the SSH standardized cipher name
	 * @param keyLength   the key length in bytes
	 * @param blockLength   the block length in bytes for block cipher
	 */
	CipherAlgorithm(String name, int keyLength, int blockLength)
	{
		this.name = name;
		this.keyLength = keyLength;
		this.blockLength = blockLength;
	}

	int getBlockLength()
	{
		return blockLength;
	}

	int getKeyLength()
	{
		return keyLength;
	}

	public String getName()
	{
		return name;
	}

	abstract Cipher getInstance(byte[] key, byte[] iv, int mode);

	static class BaseCipherAlgorithm extends CipherAlgorithm
	{
		protected String algoName;
		protected String keyName;

		public BaseCipherAlgorithm(String name,
			String algoName, String keyName,
			int keyLength, int blockLength)
		{
			super(name, keyLength, blockLength);
			this.algoName = algoName;
			this.keyName = keyName;
		}

		@Override
		Cipher getInstance(byte[] key, byte[] iv, int mode)
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
}
