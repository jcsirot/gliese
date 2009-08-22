/*
 *  Copyright 2009 sirot.
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

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import org.xulfactory.gliese.AuthenticationResult;
import org.xulfactory.gliese.Gliese;
import org.xulfactory.gliese.SSHConnection;
import org.xulfactory.gliese.SSHException;
import org.xulfactory.gliese.SSHRSAPublicKey;
import org.xulfactory.gliese.SSHTimeoutException;
import org.xulfactory.gliese.util.GlieseLogger;

/**
 *
 * @author sirot
 */
public class Main
{
	private static final BigInteger D = new BigInteger("282ce8304d2da73e5f98ad4c23399dadee1e0d7ba3662e6fec48e16e117b8a5ad41da348d23825c7b75146c7858ea4eeccf238d14c173e55292e9e20ed532e350829457e0ca364327be9ba70b9d82da7ed06ac4c5620cd6d2c503aa1de794ec62e60fdab769da9ad796f759ca19faba2b24746f37ef4f1fa23bee237104704e1", 16);
	private static final BigInteger E = new BigInteger("23", 16);
	private static final BigInteger N = new BigInteger("968ce895264e6f73cfcc6df88ad9ad4a39a4af08b16fba4be48d221af26551fdd72add8167c087d626ebf659cb03816f06965b11b5da5b9bedd88e45c170928101aeb7d95980c12a0c76af6f4ac1d9ca7099c2279769e6da19eb93c43f83bf56a529666d84c3213f853c6cf5010ca02c3501e747a2214f4a5c9610659f2bf0d3", 16);

	public static void main(String[] args)
		throws IOException, SSHException, SSHTimeoutException
	{
		GlieseLogger.LOGGER.setLevel(GlieseLogger.DEBUG);
		try {
			//SSHConnection conn = Gliese.openConnection("192.168.1.101");
			SSHConnection conn = Gliese.openConnection(args[0]);
			String username = null;
			do {
				username = System.console().readLine("Login as: ");
			} while (username == null);
			System.out.println(Arrays.toString(conn.getAuthenticationMethods(username)));
//			while (true) {
//				char[] password = System.console().readPassword("Password: ");
//				if (password == null) {
//					password = "".toCharArray();
//				}
//				AuthenticationResult res = conn.authenticate(username, password);
//				if (res.isSuccess()) {
//					break;
//				}
//			}
 			SSHRSAPublicKey pk = new SSHRSAPublicKey(N, E);
 			RSAPrivateKeySpec spec = new RSAPrivateKeySpec(N, D);
 			KeyFactory kf = KeyFactory.getInstance("RSA");
 			PrivateKey sk = kf.generatePrivate(spec);
 			Signature sig = Signature.getInstance("SHA1withRSA");
 			sig.initSign(sk);
 			AuthenticationResult res = conn.authenticate(username, pk, sig);
			conn.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.exit(0);
	}
}
