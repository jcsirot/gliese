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

/**
 *
 * @author sirot
 */
public class AuthenticationResult
{
	public enum Status {
		SUCCESS, PARTIAL_SUCCESS, FAILURE
	}
	
	private Status status;
	private String[] authenticationThatCanContinue;

	static final AuthenticationResult success()
	{
		return new AuthenticationResult(true, false, null);
	}

	static final AuthenticationResult failure(boolean partial, String[] authenticationThatCanContinue)
	{
		return new AuthenticationResult(false, partial, authenticationThatCanContinue);
	}
	
	private AuthenticationResult(boolean success, boolean partialSuccess, String[] authenticationThatCanContinue)
	{
		if (success) {
			this.status = Status.SUCCESS;
		} else if (isPartialSuccess()) {
			this.status = Status.PARTIAL_SUCCESS;
		} else {
			this.status = Status.FAILURE;
		}
		this.authenticationThatCanContinue = authenticationThatCanContinue;
	}
	
	public String[] getAuthenticationThatCanContinue()
	{
		return authenticationThatCanContinue;
	}
	
	public boolean isPartialSuccess()
	{
		return status == Status.PARTIAL_SUCCESS;
	}
	
	public boolean isSuccess()
	{
		return status == Status.SUCCESS;
	}

	public Status getStatus()
	{
		return status;
	} 
}
