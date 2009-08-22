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
 * Base implementation of {@code MacAlgorithm}.
 *
 * @author sirot
 */
public class BaseMacAlgorithm implements MacAlgorithm
{
	private String name;
	private int keyLength;
	private int blockLength;
	private String algoName;

	/**
	 * Creates an {@code MacHandler}.
	 *
	 * @param name  the SSH standardized Mac name
	 * @param name  the JCA Mac algorithm name
	 * @param blockLength   the block length in bytes
	 * @param keyLength   the key length in bytes
	 */
	public BaseMacAlgorithm(String name, String algoName,
		int blockLength, int keyLength)
	{
		this.name = name;
		this.algoName = algoName;
		this.blockLength = blockLength;
		this.keyLength = keyLength;
	}

	public int getLength()
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

	public Mac getInstance(byte[] key)
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
