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

package org.xulfactory.gliese.util;

import java.io.IOException;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 *
 * @author sirot
 */
public class GlieseLogger
{
	public static final GlieseLogger LOGGER;

	static {
		LOGGER = GlieseLogger.getInstance("org.xulfactory.gliese");
	}

	static synchronized GlieseLogger getInstance(String logCategory)
	{
		return new GlieseLogger(logCategory);
	}

	public static final String DEBUG = "DEBUG";
	public static final String INFO = "INFO";
	public static final String WARNING = "WARNING";
	public static final String ERROR = "ERROR";

	private Logger logger;

	GlieseLogger(String logCategory)
	{
		logger = Logger.getLogger(logCategory);
		try {
			Handler fh = new FileHandler("gliese.log", true);
			fh.setFormatter(new SimpleFormatter());
			logger.addHandler(fh);
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}

	public void setLevel(String level)
	{
		if (level.equalsIgnoreCase(DEBUG)) {
			logger.setLevel(Level.FINE);
		} else if (level.equalsIgnoreCase(INFO)) {
			logger.setLevel(Level.INFO);
		} else if (level.equalsIgnoreCase(WARNING)) {
			logger.setLevel(Level.WARNING);
		} else if (level.equalsIgnoreCase(ERROR)) {
			logger.setLevel(Level.SEVERE);
		} else {
			logger.setLevel(Level.INFO);
		}
	}

	public void debug(Object msg)
	{
		log(Level.FINE, msg, null);
	}

	public void info(Object msg)
	{
		log(Level.INFO, msg, null);
	}
	
	public void warn(Object msg)
	{
		log(Level.WARNING, msg, null);
	}

	public void error(Object msg)
	{
		log(Level.SEVERE, msg, null);
	}

	public void error(Throwable t)
	{
		log(Level.SEVERE, "", t);
	}

	public void error(Object msg, Throwable t)
	{
		log(Level.SEVERE, msg, t);
	}

	private void log(Level level, Object msg, Throwable thrown)
	{
		if (msg == null) {
			level = Level.SEVERE;
			msg = "Missing [msg] parameter";
		}

		if (logger.isLoggable(level)) {
			LogRecord result = new LogRecord(level, String.valueOf(msg));
			if (thrown != null) {
				result.setThrown(thrown);
			}
			StackTraceElement[] stacktrace = new Throwable().getStackTrace();
			for (int i = 0; i < stacktrace.length; i++) {
				StackTraceElement element = stacktrace[i];
				if (!element.getClassName().equals(GlieseLogger.class.getName())) {
					result.setSourceClassName(element.getClassName());
					result.setSourceMethodName(element.getMethodName());
					break;
				}
			}
			logger.log(result);
		}
	}
}
