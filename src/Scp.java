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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Stack;
import org.xulfactory.gliese.AuthenticationResult;
import org.xulfactory.gliese.Gliese;
import org.xulfactory.gliese.SSHChannel;
import org.xulfactory.gliese.SSHConnection;
import org.xulfactory.gliese.SSHException;
import org.xulfactory.gliese.util.GlieseLogger;

/**
 *
 * @author sirot
 */
public class Scp
{
	public static void main(String[] args)
		throws IOException, SSHException
	{
		GlieseLogger.LOGGER.setLevel(GlieseLogger.DEBUG);
		try {
			new Scp(args);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
		System.exit(0);
	}

	private SSHChannel channel;
	private Stack<File> dirs = new Stack<File>();

	public Scp(String[] args) throws Exception
	{
		String[] strs = parse(args[0]);
		String path = strs[0];
		String host = null;
		String username = System.getProperty("user.name");
		if (strs.length > 1) {
			host = strs[1];
		}
		if (strs.length > 2) {
			username = strs[2];
		}
		SSHConnection conn = Gliese.openConnection(host);
		System.out.println(Arrays.toString(conn.getAuthenticationMethods(username)));
		while (true) {
			char[] password = System.console().readPassword("Password: ");
			if (password == null) {
				password = "".toCharArray();
			}
			AuthenticationResult res = conn.authenticate(username, password);
			if (res.isSuccess()) {
				break;
			}
		}
		channel = conn.openSession();
		final InputStream err = channel.getErrorStream();
		channel.execCommand("scp -rf " + path);
		Thread t = new Thread() {
			public void run() {
				try {
					while (true) {
						byte[] b = new byte[1024];
						int len = err.read(b);
						if (len == -1) {
							break;
						}
						String s = new String(b, 0, len);
						System.err.print(s);
					}
				} catch (Exception e) {
					e.printStackTrace();
					System.exit(-1);
				}

			}
		};
		t.start();
		String dest = args.length > 1 ? args[1] : null;
		String curDir = System.getProperty("user.dir");
		dirs.push(new File(curDir));
		sink(dest);
		channel.close();
		System.out.println("exit status: " + channel.getExitStatus());
		conn.close();
	}

	private String[] parse(String path)
	{
		int sep = path.indexOf(":");
		if (sep == -1) {
			return new String[] {path};
		} else {
			String host = path.substring(0, sep);
			path = path.substring(sep + 1);
			sep = host.indexOf("@");
			if (sep == -1) {
				return new String[] {path, host};
			}
			String username = host.substring(0, sep);
			host = host.substring(sep + 1);
			return new String[] {path, host, username};
		}
	}

	private boolean sink(String path) throws Exception
	{
		final InputStream in = channel.getInputStream();
		channel.getOutputStream().write(0);
		BufferedReader br = new BufferedReader(new InputStreamReader(in));
		String line = br.readLine();
		String[] splited = line.split("\\s");
		if (splited[0].startsWith("E")) {
			return false;
		}
		File target;
		File parent = dirs.peek();
		if (path != null) {
			target = new File(parent, path);
			if (target.isDirectory()) {
				target = new File(target, splited[2]);
			}
		} else {
			target = new File(parent, splited[2]);
		}
		System.out.println(splited[2]);
		if (splited[0].startsWith("C")) {
			copyFile(target, Integer.parseInt(splited[1]));
		} else if (splited[0].startsWith("D")) {
			target.mkdir();
			dirs.push(target);
			channel.getOutputStream().write(0);
			boolean cont = false;
			do {
				cont = sink(null);
			} while (cont);
			dirs.pop();
			channel.getOutputStream().write(0);
		} else {
			throw new SSHException("Unsupported");
		}
		return true;
	}

	private void copyFile(File target, int len) throws Exception
	{
		final InputStream in = channel.getInputStream();
		FileOutputStream fos = new FileOutputStream(target);
		channel.getOutputStream().write(0);
		byte[] b = new byte[4096];
		while (len > 0) {
			int l = Math.min(len, b.length);
			l = in.read(b, 0, l);
			if (l == -1) {
				throw new IOException("Truncated input");
			}
			fos.write(b, 0, l);
			len -= l;
		}
		int x = in.read();
		if (x != 0) {
			throw new IOException("Unexpected input: " + x);
		}
		fos.close();
		//channel.getOutputStream().write(0);
	}
}
