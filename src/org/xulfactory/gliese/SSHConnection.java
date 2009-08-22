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

/**
 *
 * @author sirot
 */
public class SSHConnection
{
	private SSHTransport transport;
	private SSHAuthentication authentication;

	SSHConnection(String host, int port)
		throws IOException, SSHException, SSHTimeoutException
	{
		this(host, port, new DefaultAlgorithms(), null);
	}

	SSHConnection(String host, int port, HostKeyVerifier hv)
		throws IOException, SSHException, SSHTimeoutException
	{
		this(host, port, new DefaultAlgorithms(), hv);
	}

	SSHConnection(String host, int port, SSHAlgorithms algos,
		HostKeyVerifier hv)
		throws IOException, SSHException, SSHTimeoutException
	{
		GlieseLogger.LOGGER.info("Starting transport layer.");
		transport = new SSHTransport(host, port, algos, hv);
		transport.openConnection();
		GlieseLogger.LOGGER.info("Transport layer established.");
		authentication = new SSHAuthentication(transport);
	}

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
		return authentication.authenticate(username, key, signer);
	}

	public boolean isAuthenticated()
	{
		return  authentication.isAuthenticated();
	}

	public SSHTransport getTransport()
	{
		return transport;
	}

	public void close()
	{
		transport.close();
	}
}
