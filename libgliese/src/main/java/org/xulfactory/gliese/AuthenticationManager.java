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

import org.xulfactory.gliese.message.KeyboardInteractiveMethodData;
import org.xulfactory.gliese.message.ServiceAcceptMessage;
import org.xulfactory.gliese.message.ServiceRequestMessage;
import org.xulfactory.gliese.message.PasswordMethodData;
import org.xulfactory.gliese.message.PublicKeyMethodData;
import org.xulfactory.gliese.message.SSHMessage;
import org.xulfactory.gliese.message.UserAuthRequestMessage;
import org.xulfactory.gliese.message.UserAuthBannerMessage;
import org.xulfactory.gliese.message.UserAuthFailureMessage;
import org.xulfactory.gliese.message.UserAuthSuccessMessage;
import org.xulfactory.gliese.util.GlieseLogger;
import org.xulfactory.gliese.util.Utils;
import org.xulfactory.gliese.message.UserAuthInfoRequest;
import org.xulfactory.gliese.message.UserAuthInfoResponse;
import org.xulfactory.gliese.message.UserAuthPublicKeyOk;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Iterator;

/**
 *
 * @author sirot
 */
class AuthenticationManager
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

	public AuthenticationManager(SSHTransport transport) throws SSHException
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
		GlieseLogger.LOGGER.info(String.format("Listing authentication methods user='%s'", username));
		return sendAuthentication(new MethodsAuthenticationDialog(username)).getAuthenticationThatCanContinue();
	}

	AuthenticationResult authenticate(String username, char[] password)
		throws SSHException
	{
		GlieseLogger.LOGGER.info(String.format("Starting authentication user='%s', method='%s'", username, "password"));
		AuthenticationResult result = sendAuthentication(new PasswordAuthenticationDialog(username, password));
		log(result, username, "password");
		return result;
	}

	AuthenticationResult authenticate(String username, SSHPublicKey key, Signature signer)
		throws SSHException
	{
		GlieseLogger.LOGGER.info(String.format("Starting authentication user='%s', method='%s'", username, "publickey"));
		AuthenticationResult result = sendAuthentication(new PublicKeyAuthenticationDialog(username, key, signer, transport));
		log(result, username, "publickey");
		return result;
	}
	
	AuthenticationResult authenticate(String username, final KeyboardInteraction kbi)
		throws SSHException
	{
		GlieseLogger.LOGGER.info(String.format("Starting authentication user='%s', method='%s'", username, "keyboard-interactive"));
		AuthenticationResult result = sendAuthentication(new KeyboardInteractiveDialog(username, kbi));
		log(result, username, "keyboard-interactive");
		return result;
	}

	private AuthenticationResult sendAuthentication(AuthenticationDialog cb)
		throws SSHException
	{
		AuthenticationResult result = null;
		SSHMessage msg = null;
		while (result == null) {
			transport.writeMessage(cb.interact(msg));
			msg = transport.readMessage(cb.getMethod()); //FIXME
			switch (msg.getID()) {
			case UserAuthBannerMessage.ID:
				String message = ((UserAuthBannerMessage)msg).getMessage();
				System.out.println(message);
				break;
			case UserAuthFailureMessage.ID:
				result = generateFailure((UserAuthFailureMessage)msg);
				break;
			case UserAuthSuccessMessage.ID:
				result = AuthenticationResult.success();
				authenticated = true;
				break;
			default:
				if (msg.getID() < 60 || msg.getID() > 69) {
					GlieseLogger.LOGGER.error(String.format("Unexpected server message with ID=%d", msg.getID()));
					throw new SSHException("Unexpected server message");
				}
			}
		}
		return result;
	}
	
	/**
	 * Generate a failure authentication result
	 * 
	 * @param fail  the server failure message
	 * @return the {@code AuthenticationResult}
	 */
	AuthenticationResult generateFailure(UserAuthFailureMessage fail)
	{
		AuthenticationResult result = AuthenticationResult.failure(
			fail.isPartialSuccess(),
			fail.getAuthenticationsThatCanContinue());
		return result;
	}
	
	/**
	 * Handles messages between the server and the client for authentication
	 */
	private static abstract class AuthenticationDialog
	{
		private final String username;
		
		protected AuthenticationDialog(String username)
		{
			this.username = username;
		}
		
		protected String getUsername()
		{
			return username;
		}
		
		/**
		 * Initializes a new {@code UserAuthRequestMessage} with the username
		 * and the requested service.
		 * 
		 * @return a new {@code UserAuthRequestMessage}
		 */
		protected UserAuthRequestMessage initUserAuthRequestMessage()
		{
			UserAuthRequestMessage msg = new UserAuthRequestMessage();
			msg.setUser(username);
			msg.setService("ssh-connection");
			return msg;
		}
	
		/**
		 * Retrieves the authentication method name. This name is used to 
		 * distinguish messages sharing the same ID.
		 * 
		 * @return the method name
		 */
		public abstract String getMethod();
		
		/**
		 * Read the last message from the server and send a response message.
		 * @param lastMessage the server last message. May be {@code null}
		 * for the first messsage; in that case the returned message must be
		 * a {@code UserAuthRequestMessage}.
		 * 
		 * @return the client response message in the authentication dialog with
		 * the server
		 */
		public abstract SSHMessage interact(SSHMessage lastMessage)
				throws SSHException;
	}
	
	private static class MethodsAuthenticationDialog extends AuthenticationDialog
	{
		MethodsAuthenticationDialog(String username)
		{
			super(username);
		}
		
		@Override
		public SSHMessage interact(SSHMessage lastMessage)
		{
			return initUserAuthRequestMessage();
		}

		@Override
		public String getMethod()
		{
			return "none";
		}
	}
	
	private static class PublicKeyAuthenticationDialog extends AuthenticationDialog
	{
		private final SSHPublicKey key;
		private final Signature signer;
		private final SSHTransport transport;

		public PublicKeyAuthenticationDialog(String username, SSHPublicKey key, Signature signer, SSHTransport transport)
		{
			super(username);
			this.key = key;
			this.signer = signer;
			this.transport = transport;
		}

		@Override
		public String getMethod()
		{
			return "publickey";
		}

		@Override
		public SSHMessage interact(SSHMessage lastMessage) throws SSHException
		{
			if (lastMessage == null) {
				UserAuthRequestMessage msg = initUserAuthRequestMessage();
				PublicKeyMethodData md = new PublicKeyMethodData(key.getName(), key.encode());
				msg.setAuthenticationData(md);
				return msg;
			} else if (lastMessage.getID() == UserAuthPublicKeyOk.ID) {
				UserAuthRequestMessage msg = initUserAuthRequestMessage();
				PublicKeyMethodData md = new PublicKeyMethodData(key.getName(), key.encode());
				md.prepareTBS();
				msg.setAuthenticationData(md);
				byte[] sig = null;
				try {
					signer.update(Utils.encodeBytes(transport.getSessionId()));
					signer.update(msg.getEncoding());
					sig = signer.sign();
				} catch (SignatureException e) {
					throw new SSHException("Signature failed", e);
				}
				md = new PublicKeyMethodData(key.getName(), key.encode());
				md.setSignature(sig);
				msg.setAuthenticationData(md);
				return msg;
			}
			throw new UnsupportedOperationException("Not supported yet.");
		}
	}

	private static class PasswordAuthenticationDialog extends AuthenticationDialog 
	{
		private final char[] password;

		public PasswordAuthenticationDialog(String username, char[] password)
		{
			super(username);
			this.password = password;
		}
		
		@Override
		public SSHMessage interact(SSHMessage lastMessage)
		{
			UserAuthRequestMessage msg = initUserAuthRequestMessage();
			msg.setAuthenticationData(new PasswordMethodData(password));
			return msg;
		}

		@Override
		public String getMethod()
		{
			return "password";
		}
	}
	
	private static class KeyboardInteractiveDialog extends AuthenticationDialog
	{
		private final KeyboardInteraction kbi;

		public KeyboardInteractiveDialog(String username, KeyboardInteraction kbi)
		{
			super(username);
			this.kbi = kbi;
		}
		
		@Override
		public SSHMessage interact(SSHMessage lastMessage)
		{
			if (lastMessage == null) {
				UserAuthRequestMessage msg = initUserAuthRequestMessage();
				msg.setAuthenticationData(new KeyboardInteractiveMethodData(""));
				return msg;
			}
			UserAuthInfoRequest req = (UserAuthInfoRequest)lastMessage;
			if (req.getInstruction() != null) {
				kbi.prompt(req.getInstruction());
			}
			Iterator<UserAuthInfoRequest.Prompt> it = req.promptIterator();
			UserAuthInfoResponse rsp = new UserAuthInfoResponse();
			while (it.hasNext()) {
				UserAuthInfoRequest.Prompt prompt = it.next();
				String reply = kbi.reply(prompt.getPrompt(), prompt.isEcho());
				rsp.addResponse(reply);
			}
			return rsp;
		}

		@Override
		public String getMethod()
		{
			return "keyboard-interactive";
		}
	}
}
