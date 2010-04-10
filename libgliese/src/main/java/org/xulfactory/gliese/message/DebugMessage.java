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

/**
 *
 * @author sirot
 */
public class DebugMessage extends SSHMessage
{
	public static final int ID = 4;

	private boolean alwaysDisplay;
	private String message;
	private String tag;

	public DebugMessage()
	{
		super(ID);
	}

	@Override
	protected void decode(InputStream in) throws IOException
	{
		alwaysDisplay = Utils.decodeBoolean(in);
		message = Utils.decodeStringUTF8(in);
		tag = Utils.decodeString(in);
	}

	@Override
	protected void encode(OutputStream out) throws IOException
	{
		Utils.encodeBoolean(out, alwaysDisplay);
		Utils.encodeStringUTF8(out, message);
		Utils.encodeString(out, tag);
	}

	public boolean isAlwaysDisplay()
	{
		return alwaysDisplay;
	}

	public String getMessage()
	{
		return message;
	}

	public String getTag()
	{
		return tag;
	}

	public void setAlwaysDisplay(boolean alwaysDisplay)
	{
		this.alwaysDisplay = alwaysDisplay;
	}

	public void setMessage(String message)
	{
		this.message = message;
	}

	public void setTag(String tag)
	{
		this.tag = tag;
	}
}
