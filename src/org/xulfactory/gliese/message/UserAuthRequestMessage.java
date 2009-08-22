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

package org.xulfactory.gliese.message;

import java.io.ByteArrayOutputStream;
import org.xulfactory.gliese.util.Utils;
import org.xulfactory.gliese.message.PasswordMethodData.PasswordMethodCodec;
import org.xulfactory.gliese.message.KeyboardInteractiveMethodData.KeyboardInteractiveMethodCodec;
import org.xulfactory.gliese.message.PublicKeyMethodData.PublicKeyMethodCodec;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author sirot
 */
public class UserAuthRequestMessage extends SSHMessage
{
	public static final int ID = 50;

	private static Map<String, AuthenticationMethodCodec> methods
		= new HashMap<String, AuthenticationMethodCodec>();

	public static void register(String method, AuthenticationMethodCodec d)
	{
		methods.put(method, d);
	}

	static {
		register(PasswordMethodData.METHOD, new PasswordMethodCodec());
		register(PublicKeyMethodData.METHOD, new PublicKeyMethodCodec());
		register(KeyboardInteractiveMethodData.METHOD, new KeyboardInteractiveMethodCodec());
	}

	private String user;
	private String service;
	private	String method;
	private AuthenticationMethodData authData;

	public UserAuthRequestMessage()
	{
		super(ID);
	}

	@Override
	protected void decode(InputStream in) throws IOException
	{
		user = Utils.decodeStringUTF8(in);
		service = Utils.decodeString(in);
		method = Utils.decodeString(in);
		authData = decode(method, in);
	}

	@Override
	protected void encode(OutputStream out) throws IOException
	{
		Utils.encodeStringUTF8(out, user);
		Utils.encodeString(out, service);
		encode(out, authData);
	}

	public String getMethod()
	{
		return method;
	}

	public String getService()
	{
		return service;
	}

	public String getUser()
	{
		return user;
	}

	protected void setMethod(String method)
	{
		this.method = method;
	}

	public void setService(String service)
	{
		this.service = service;
	}

	public void setUser(String user)
	{
		this.user = user;
	}

	public AuthenticationMethodData getAuthenticationData()
	{
		return authData;
	}

	public void setAuthenticationData(AuthenticationMethodData authData)
	{
		this.authData = authData;
	}

	private AuthenticationMethodData decode(String method, InputStream in)
		throws IOException
	{
		AuthenticationMethodCodec codec = methods.get(method);
		return codec.decode(in);
	}

	private void encode(OutputStream out, AuthenticationMethodData authData)
		throws IOException
	{
		if (authData == null) {
			method = "none";
			Utils.encodeString(out, method);
		} else {
			method = authData.getMethod();
			Utils.encodeString(out, method);
			AuthenticationMethodCodec codec = methods.get(method);
			codec.encode(out, authData);
		}
	}

	public abstract static interface AuthenticationMethodData
	{
		String getMethod();
	}

	public abstract static interface AuthenticationMethodCodec<
		E extends AuthenticationMethodData>
	{
		E decode(InputStream in) throws IOException;

		void encode(OutputStream out, E e) throws IOException;
	}

	public byte[] getEncoding()
	{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			out.write(ID);
			encode(out);
		} catch (IOException ioe) {
			/* Does not happen */
			throw new Error(ioe);
		}
		return out.toByteArray();
	}
}
