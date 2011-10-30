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
import java.util.Iterator;
import java.util.List;

/**
 *
 * @author sirot
 */
public class UserAuthInfoRequest extends SSHMessage
{
	public static final int ID = 60;

	private String name;
	private String instruction;
	private List<Prompt> prompts;
	
	/**
	 * Creates a new {@code UserAuthInfoRequest}
	 */
	public UserAuthInfoRequest()
	{
		super(ID);
		prompts = new ArrayList<Prompt>();
	}

	@Override
	protected void decode(InputStream in) throws IOException
	{
		name = Utils.decodeStringUTF8(in);
		instruction = Utils.decodeStringUTF8(in);
		Utils.decodeString(in); // Drop obsolote language tag
		int numPrompts = Utils.decodeInt(in);
		for (int i = 0; i < numPrompts; i++) {
			prompts.add(new Prompt(Utils.decodeString(in), Utils.decodeBoolean(in)));
		}
	}

	@Override
	protected void encode(OutputStream out) throws IOException
	{
		Utils.encodeString(out, name);
		Utils.encodeString(out, instruction);
		Utils.encodeString(out, "");
		Utils.encodeInt(prompts.size());
		for (Prompt prompt: prompts) {
			Utils.encodeString(out, prompt.getPrompt());
			Utils.encodeBoolean(out, prompt.isEcho());
		}
	}

	/**
	 * Retrieves the authentication instruction
	 * @return the instruction
	 */
	public String getInstruction()
	{
		return instruction;
	}

	/**
	 * Retrieves the authentication name
	 * @return the name
	 */
	public String getName()
	{
		return name;
	}

	public void setInstruction(String instruction)
	{
		this.instruction = instruction;
	}

	public void setName(String name)
	{
		this.name = name;
	}

	public Iterator<Prompt> promptIterator()
	{
		return prompts.iterator();
	}
	
	/**
	 * Adds a prompt message
	 * 
	 * @param prompt the prompt
	 */
	public void addPrompt(Prompt prompt)
	{
		prompts.add(prompt);
	}
	
	public static class Prompt
	{
		private String prompt;
		private boolean echo;

		public Prompt(String prompt, boolean echo)
		{
			this.prompt = prompt;
			this.echo = echo;
		}

		public boolean isEcho()
		{
			return echo;
		}

		public String getPrompt()
		{
			return prompt;
		}
	}
}