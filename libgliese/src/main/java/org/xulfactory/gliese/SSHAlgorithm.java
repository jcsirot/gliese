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
 * This interface must be implemented by all algorithms.
 *
 *
 * @author sirot
 */
public interface SSHAlgorithm
{
	/**
	 * Retrieves the name of the algorithm as defined in the SSH2 reference.
	 * For instance des3-cbc, aes128-cbc, hmac-sha1, ssh-dss...
	 *
	 * @return  the algorithm SSH name
	 */
	String getName();
}
