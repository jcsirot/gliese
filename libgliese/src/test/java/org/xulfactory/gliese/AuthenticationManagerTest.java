/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.xulfactory.gliese;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import org.mockito.InOrder;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import org.junit.Before;
import org.junit.Ignore;
import org.mockito.Mock;
import org.xulfactory.gliese.message.ServiceAcceptMessage;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatcher;
import org.mockito.runners.MockitoJUnitRunner;
import org.xulfactory.gliese.algo.SSHRSAPublicKey;
import org.xulfactory.gliese.message.PublicKeyMethodData;
import org.xulfactory.gliese.message.SSHMessage;
import org.xulfactory.gliese.message.UserAuthFailureMessage;
import org.xulfactory.gliese.message.UserAuthInfoRequest;
import org.xulfactory.gliese.message.UserAuthPublicKeyOk;
import org.xulfactory.gliese.message.UserAuthRequestMessage;
import org.xulfactory.gliese.message.UserAuthSuccessMessage;
import org.xulfactory.gliese.util.Utils;
import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

/**
 *
 * @author sirot
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthenticationManagerTest
{
	@Mock 
	private SSHTransport transport;
	private AuthenticationManager authMgr;
	
	@Before
	public void setUp() throws SSHException
	{
		ServiceAcceptMessage sam = new ServiceAcceptMessage();
		sam.setServiceName("ssh-userauth");
		when(transport.readMessage()).thenReturn(sam);
		authMgr = new AuthenticationManager(transport);
	}
	
	@Test
	public void shouldAuthenticateWithPassword() throws Exception
	{
		// Given
		UserAuthSuccessMessage uasm = new UserAuthSuccessMessage();
		when(transport.readMessage("password")).thenReturn(uasm);
		// When
		AuthenticationResult res = authMgr.authenticate("user", "password".toCharArray());
		// Then
		assertTrue("Authentication should succeeds", res.isSuccess());
	}

	@Test
	public void shouldNotAuthenticateWithPassword() throws Exception
	{
		// Given
		UserAuthFailureMessage uafm = new UserAuthFailureMessage();
		when(transport.readMessage("password")).thenReturn(uafm);
		// When
		AuthenticationResult res = authMgr.authenticate("user", "password".toCharArray());
		// Then
		assertFalse("Authentication should not succeed", res.isSuccess());
	}
	
	@Test
	public void shouldAuthenticateWithKeyboardInteractive() throws Exception
	{
		// Given
		UserAuthInfoRequest uair = new UserAuthInfoRequest();
		uair.addPrompt(new UserAuthInfoRequest.Prompt("Enter password:", false));
		UserAuthSuccessMessage uasm = new UserAuthSuccessMessage();
		when(transport.readMessage("keyboard-interactive")).thenReturn(uair).thenReturn(uasm);
		KeyboardInteraction kbi = mock(KeyboardInteraction.class);
		// When
		AuthenticationResult res = authMgr.authenticate("user", kbi);
		// Then
		verify(kbi, never()).prompt(anyString());
		verify(kbi).reply("Enter password:", false);
		assertTrue("Authentication should succeeds", res.isSuccess());
	}
	
	@Test
	public void shouldCorrectlyHandleTheAuthenticationMethods() throws Exception
	{
		// Given
		UserAuthFailureMessage uafm = new UserAuthFailureMessage();
		uafm.setAuthenticationsThatCanContinue(new String[] {"publickey"});
		when(transport.readMessage(anyString())).thenReturn(uafm);
		// When
		String[] methods = authMgr.getAuthenticationMethods("user");
		// Then
		assertEquals(1, methods.length);
		assertEquals("publickey", methods[0]);
	}
	
	@Test
	public void shouldGenerateFailureAuthenticationResult() throws Exception
	{
		// Given
		UserAuthFailureMessage uafm = new UserAuthFailureMessage();
		// When
		AuthenticationResult result = authMgr.generateFailure(uafm);
		// Then
		assertFalse("Result should not be success", result.isSuccess());
	}
	
	@Test
	public void shouldNotAuthenticateWithPublicKey() 
			throws SSHException, NoSuchAlgorithmException, InvalidKeyException
	{
		// Given
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(1024);
		KeyPair kp = kpg.generateKeyPair();
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(kp.getPrivate());
		final SSHPublicKey pkey = new SSHRSAPublicKey(
				((RSAPublicKey)kp.getPublic()).getModulus(),
				((RSAPublicKey)kp.getPublic()).getPublicExponent());
		UserAuthFailureMessage uafm = new UserAuthFailureMessage();
		when(transport.readMessage("publickey")).thenReturn(uafm);
		when(transport.getSessionId()).thenReturn(new byte[20]);
		// When
		AuthenticationResult res = authMgr.authenticate("user", pkey, signature);
		// Then
		InOrder inorder = inOrder(transport);
		inorder.verify(transport, times(1)).writeMessage(any(SSHMessage.class));
		inorder.verify(transport, times(1)).writeMessage(argThat(new ArgumentMatcher<SSHMessage>() {
			@Override
			public boolean matches(Object arg)
			{
				UserAuthRequestMessage msg = (UserAuthRequestMessage)arg;
				assertTrue(msg.getAuthenticationData() instanceof PublicKeyMethodData);
				assertEquals("publickey", msg.getMethod());
				PublicKeyMethodData md = (PublicKeyMethodData)msg.getAuthenticationData();
				assertEquals("ssh-rsa", md.getAlgorithm());
				assertArrayEquals(pkey.encode(), md.getPubkey());
				return true;
			}
		}));
		assertFalse("Authentication should not succeed", res.isSuccess());		
	}

	@Test
	public void shouldAuthenticateWithPublicKey() 
			throws SSHException, NoSuchAlgorithmException, InvalidKeyException
	{
		// Given
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(1024);
		KeyPair kp = kpg.generateKeyPair();
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(kp.getPrivate());
		final PublicKey publickey = kp.getPublic();
		final SSHPublicKey pkey = new SSHRSAPublicKey(
				((RSAPublicKey)kp.getPublic()).getModulus(),
				((RSAPublicKey)kp.getPublic()).getPublicExponent());
		UserAuthPublicKeyOk uapkok = new UserAuthPublicKeyOk();
		uapkok.setAlgorithm("ssh-rsa");
		uapkok.setPubkey(pkey.encode());
		UserAuthSuccessMessage uasm = new UserAuthSuccessMessage();
		when(transport.readMessage("publickey")).thenReturn(uapkok).thenReturn(uasm);
		when(transport.getSessionId()).thenReturn(new byte[20]);
		// When
		AuthenticationResult res = authMgr.authenticate("user", pkey, signature);
		// Then
		InOrder inorder = inOrder(transport);
		inorder.verify(transport, times(1)).writeMessage(any(SSHMessage.class));
		inorder.verify(transport, times(1)).writeMessage(any(SSHMessage.class));
		inorder.verify(transport, times(1)).writeMessage(argThat(new ArgumentMatcher<SSHMessage>() {
			@Override
			public boolean matches(Object arg)
			{
				UserAuthRequestMessage msg = (UserAuthRequestMessage)arg;
				assertTrue(msg.getAuthenticationData() instanceof PublicKeyMethodData);
				assertEquals("publickey", msg.getMethod());
				PublicKeyMethodData md = (PublicKeyMethodData)msg.getAuthenticationData();
				assertEquals("ssh-rsa", md.getAlgorithm());
				assertArrayEquals(pkey.encode(), md.getPubkey());
				assertNotNull(md.getSignature());
				try {
					Signature verify = Signature.getInstance("SHA1withRSA");
					verify.initVerify(publickey);
					ByteArrayOutputStream out = new ByteArrayOutputStream();
					Utils.encodeBytes(out, new byte[20]);
					out.write((byte)50);
					Utils.encodeString(out, "user");
					Utils.encodeString(out, "ssh-connection");
					Utils.encodeString(out, "publickey");
					Utils.encodeBoolean(out, true);
					Utils.encodeString(out, "ssh-rsa");
					Utils.encodeBytes(out, pkey.encode());
					verify.update(out.toByteArray());
					assertTrue("Signature should be verified", verify.verify(md.getSignature()));
				} catch (InvalidKeyException ike) {
					fail(ike.getMessage());
				} catch (NoSuchAlgorithmException nsae) {
					fail(nsae.getMessage());
				} catch (IOException ioe) {
					fail(ioe.getMessage());
				} catch (SignatureException se) {
					fail(se.getMessage());
				}
				return true;
			}
		}));
		assertTrue("Authentication should succeed", res.isSuccess());		
	}
}
