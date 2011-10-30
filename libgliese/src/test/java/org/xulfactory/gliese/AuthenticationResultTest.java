/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.xulfactory.gliese;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author sirot
 */
public class AuthenticationResultTest
{
	@Test
	public void shouldBeFailure()
	{
		// Given
		// When
		AuthenticationResult result = AuthenticationResult.failure(false, null);
		// Then
		assertFalse("Should not be a success", result.isSuccess());
	}
	
	@Test
	public void shouldBeSuccess()
	{
		// Given
		// When
		AuthenticationResult result = AuthenticationResult.success();
		// Then
		assertTrue("Should be a success", result.isSuccess());
	}
}
