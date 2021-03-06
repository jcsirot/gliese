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

import org.xulfactory.gliese.util.GlieseLogger;

import java.io.IOException;
import java.security.Signature;
import java.util.Properties;

/**
 * This class represents a connection with the server. Once connected the
 * first thing to do is calling is one of the {@code authenticate} methods.
 *
 * @author sirot
 */
public class SSHConnection
{
	private final AlgorithmRegistry registry;
	private final Properties properties;
	private final KexInitAlgorithms algos;
	private HostKeyVerifier hv;
	private SSHTransport transport;
	private AuthenticationManager authentication;
	private ChannelManager channels;

	SSHConnection(AlgorithmRegistry registry, Properties props)
	{
		this.registry = registry;
		this.properties = props != null ? props : new Properties();
		this.algos = new DefaultAlgorithms(registry, properties);
	}

	public void setHostKeyVerifier(HostKeyVerifier hv)
	{
		this.hv = hv;
	}

	public void openConnection(String host, int port)
		throws IOException, SSHException
	{
		GlieseLogger.LOGGER.info("Starting transport layer.");
		transport = new SSHTransport(host, port, algos, hv);
		transport.openConnection();
		GlieseLogger.LOGGER.info("Transport layer established.");
		authentication = new AuthenticationManager(transport);
		channels = new ChannelManager(transport);
	}

	/**
	 * Retrieves the allowed authentication methods for the given user.
	 *
	 * @param username   the user name
	 * @return  a list of authentication method for the user
	 * @throws SSHException
	 */
	public String[] getAuthenticationMethods(String username)
		throws SSHException
	{
		return authentication.getAuthenticationMethods(username);
	}

	public AuthenticationResult authenticate(String username, char[] password)
		throws SSHException
	{
		return authentication.authenticate(username, password);
	}

	public AuthenticationResult authenticate(String username, SSHPublicKey key, Signature signer)
		throws SSHException
	{
		//return authentication.authenticate(username, key, signer);
		throw new UnsupportedOperationException();
	}

	public AuthenticationResult authenticate(String username, KeyboardInteraction kbi)
		throws SSHException
	{
		return authentication.authenticate(username, kbi);
	}
	
	public SSHChannel openSession() throws SSHException
	{
		if (!isAuthenticated()) {
			throw new IllegalStateException(
				"Connection is not authenticated");
		}
		return channels.openSession();
	}

	/**
	 * Indicates if the authentication has been successfully completed.
	 */
	public boolean isAuthenticated()
	{
		return  authentication.isAuthenticated();
	}

	public SSHTransport getTransport()
	{
		return transport;
	}

	/**
	 * Closes the connection with the server.
	 */
	public void close()
	{
		transport.close();
	}
}
