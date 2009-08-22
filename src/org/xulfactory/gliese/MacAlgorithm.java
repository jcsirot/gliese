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

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author sirot
 */
public abstract class MacAlgorithm implements SSHAlgorithm
{
	private String name;
	private int keyLength;
	private int blockLength;

	/**
	 * Creates an {@code MacHandler}.
	 *
	 * @param name  the SSH standardized Mac name
	 * @param keyLength   the key length in bytes
	 * @param blockLength   the block length in bytes
	 */
	MacAlgorithm(String name, int keyLength, int blockLength)
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

	abstract Mac getInstance(byte[] key);

	static class BaseMacHandler extends MacAlgorithm
	{
		protected String algoName;

		public BaseMacHandler(String name, String algoName,
			int keyLength, int blockLength)
		{
			super(name, keyLength, blockLength);
			this.algoName = algoName;
		}

		@Override
		Mac getInstance(byte[] key)
		{
			try {
				Mac mac = Mac.getInstance(algoName);
				Key skey = new SecretKeySpec(key, algoName);
				mac.init(skey);
				return mac;
			} catch (NoSuchAlgorithmException nsae) {
				throw new Error(nsae);// FIXME
			} catch (InvalidKeyException ike) {
				throw new Error(ike);// FIXME
			}
		}
	}
}
