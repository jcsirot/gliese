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

import org.xulfactory.gliese.util.Utils;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author sirot
 */
public class UserAuthInfoResponse extends SSHMessage
{
	public static final int ID = 61;

	private List<String> responses;
	
	public UserAuthInfoResponse()
	{
		super(ID);
		responses = new ArrayList<String>();
	}

	@Override
	protected void decode(InputStream in) throws IOException
	{
		int numResponses = Utils.decodeInt(in);
		for (int i = 0; i < numResponses; i++) {
			responses.add(Utils.decodeString(in));
		}
	}

	@Override
	protected void encode(OutputStream out) throws IOException
	{
		Utils.encodeInt(out, responses.size());
		for (String response: responses) {
			Utils.encodeString(out, response);
		}
	}
	
	public void addResponse(String response)
	{
		responses.add(response);
	}
}