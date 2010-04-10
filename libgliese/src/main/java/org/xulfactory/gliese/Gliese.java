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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * <strong>Entry point of the library.</strong>
 *
 * @author sirot
 */
public final class Gliese
{
	private static AlgorithmRegistry registry = new AlgorithmRegistry();
	private static Properties properties = null;

	/**
	 * Opens the connection with a SSH server on the default port (22).
	 *
	 * @param host  the SSH server host name
	 * @return the {@code SSHConnection}
	 * @throws SSHException
	 * @throws IOException
	 */
	public static SSHConnection openConnection(String host)
		throws SSHException, IOException
	{
		return openConnection(host, 22);
	}

	/**
	 * Opens the connection with a SSH server.
	 *
	 * @param host  the SSH server host name
	 * @param port  the SSH server host port
	 * @return the {@code SSHConnection}
	 * @throws SSHException
	 * @throws IOException
	 */
	public static SSHConnection openConnection(String host, int port)
			throws SSHException, IOException
	{
		SSHConnection con = new SSHConnection(registry, properties);
		con.openConnection(host, port);
		return con;
	}

	/**
	 * Sets the library properties
	 *
	 * @param props the property file
	 */
	public static void setProperties(File props) throws IOException
	{
		setProperties(new FileInputStream(props));
	}

	/**
	 * Sets the library properties
	 *
	 * @param props the properties
	 */
	public static void setProperties(Properties props)
	{
		properties = props;
	}

	/**
	 * Sets the library properties
	 *
	 * @param props the property file path
	 */
	public static void setProperties(String props) throws IOException
	{
		setProperties(new File(props));
	}

	/**
	 * Sets the library properties
	 *
	 * @param props the property stream
	 */
	public static void setProperties(InputStream props) throws IOException
	{
		properties = new Properties();
		properties.load(props);
	}

	private Gliese()
	{
	}
}
