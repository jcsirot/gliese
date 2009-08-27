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

import java.io.IOException;

/**
 * <strong>Entry point of the library.</strong>
 *
 * @author sirot
 */
public final class Gliese
{
	public static SSHConnection openConnection(String host)
		throws SSHException, IOException
	{
		return openConnection(host, 22);
	}

	public static SSHConnection openConnection(String host, int port)
			throws SSHException, IOException
	{
		SSHConnection con = new SSHConnection(host, port);
		return con;
	}

	private Gliese()
	{
	}
}
