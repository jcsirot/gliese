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

import javax.crypto.Mac;

/**
 * Message authentication code algorithm interface.
 *
 * @author sirot
 */
public interface MacAlgorithm extends SSHAlgorithm
{
	/**
	 * Retrieves the Mac output length in bytes.
	 *
	 * @return  the mac length
	 */
	int getLength();

	/**
	 * Retrieves the length of the key in bytes.
	 *
	 * @return  the Mac key length
	 */
	int getKeyLength();

	/**
	 * Retrieves an instance of the Mac algorithm initialized with
	 * the provided key.
	 *
	 * @param key  the key
	 * @return  the Mac instance
	 */
	Mac getInstance(byte[] key);
}
