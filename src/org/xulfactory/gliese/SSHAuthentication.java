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

import org.xulfactory.gliese.message.ServiceAcceptMessage;
import org.xulfactory.gliese.message.ServiceRequestMessage;
import org.xulfactory.gliese.message.PasswordMethodData;
import org.xulfactory.gliese.message.PublicKeyMethodData;
import org.xulfactory.gliese.message.SSHMessage;
import org.xulfactory.gliese.message.UserAuthRequestMessage;
import org.xulfactory.gliese.message.UserAuthBannerMessage;
import org.xulfactory.gliese.message.UserAuthFailureMessage;
import org.xulfactory.gliese.message.UserAuthPublicKeyOk;
import org.xulfactory.gliese.message.UserAuthSuccessMessage;
import org.xulfactory.gliese.util.GlieseLogger;
import org.xulfactory.gliese.util.Utils;

import java.security.Signature;

/**
 *
 * @author sirot
 */
public class SSHAuthentication
{
	private static void log(AuthenticationResult res, String username, String method)
	{
		if (res.isSuccess()) {
			GlieseLogger.LOGGER.info(String.format("Authentication granted user='%s', method='%s'", username, method));
		} else if (res.isPartialSuccess()) {
			GlieseLogger.LOGGER.info(String.format("Authentication partial success user='%s', method='%s'", username, method));
		} else {
			GlieseLogger.LOGGER.info(String.format("Authentication failed user='%s', method='%s'", username, method));
		}
	}

	private final SSHTransport transport;
	private boolean authenticated;

	public SSHAuthentication(SSHTransport transport) throws SSHException
	{
		this.transport = transport;
		requestService();
		authenticated = false;
	}

	private void requestService() throws SSHException
	{
		ServiceRequestMessage srm = new ServiceRequestMessage();
		srm.setServiceName("ssh-userauth");
		transport.writeMessage(srm);
		ServiceAcceptMessage sam =
			(ServiceAcceptMessage)transport.readMessage();
		if (!sam.getServiceName().equals("ssh-userauth")) {
			GlieseLogger.LOGGER.error("Accepted service: " +
				sam.getServiceName() + "(!?)");
		}
	}

	boolean isAuthenticated()
	{
		return authenticated;
	}

	public String[] getAuthenticationMethods(String username)
		throws SSHException
	{
		UserAuthRequestMessage pm = new UserAuthRequestMessage();
		pm.setUser(username);
		pm.setService("ssh-connection");
		return sendAuthentication(pm).getAuthenticationThatCanContinue();
	}

	AuthenticationResult authenticate(String username, char[] password)
		throws SSHException
	{
		GlieseLogger.LOGGER.info(String.format("Starting authentication user='%s', method='%s'", username, "password"));
		UserAuthRequestMessage pm = new UserAuthRequestMessage();
		pm.setUser(username);
		pm.setService("ssh-connection");
		pm.setAuthenticationData(new PasswordMethodData(password));
		AuthenticationResult result = sendAuthentication(pm);
		log(result, username, "password");
		return result;
	}

	AuthenticationResult authenticate(String username, SSHPublicKey key, Signature signer)
		throws SSHException
	{
		GlieseLogger.LOGGER.info(String.format("Starting authentication user='%s', method='%s'", username, "publickey"));
		UserAuthRequestMessage pm = new UserAuthRequestMessage();
		pm.setUser(username);
		pm.setService("ssh-connection");
		PublicKeyMethodData md = new PublicKeyMethodData(key.getName(), key.encode());
		md.prepareTBS();
		pm.setAuthenticationData(md);
		byte[] sig = null;
		try {
			signer.update(Utils.encodeBytes(transport.getSessionId()));
			signer.update(pm.getEncoding());
			sig = signer.sign();
		} catch (Exception e) {
			throw new SSHException("Signature failed", e);
		}
		md = new PublicKeyMethodData(key.getName(), key.encode());
		md.setSignature(sig);
		pm.setAuthenticationData(md);
		AuthenticationResult result = sendAuthentication(pm);
		log(result, username, "publickey");
		return result;
	}

	private AuthenticationResult sendAuthentication(UserAuthRequestMessage req)
		throws SSHException
	{
		transport.writeMessage(req);
		AuthenticationResult result = null;
		while (result == null) {
			SSHMessage msg = transport.readMessage();
			switch (msg.getID()) {
			case UserAuthBannerMessage.ID:
				String message = ((UserAuthBannerMessage)msg).getMessage();
				System.out.println(message);
				break;
			case UserAuthFailureMessage.ID:
				UserAuthFailureMessage fail = (UserAuthFailureMessage)msg;
				result = AuthenticationResult.failure(
					fail.isPartialSuccess(),
					fail.getAuthenticationsThatCanContinue());
				break;
			case UserAuthSuccessMessage.ID:
				result = AuthenticationResult.success();
				authenticated = true;
				break;
			case UserAuthPublicKeyOk.ID:
				throw new UnsupportedOperationException();
			}
		}
		return result;
	}
}
