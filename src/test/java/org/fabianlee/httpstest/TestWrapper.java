package org.fabianlee.httpstest;

import org.junit.Test;

import javahttpstest.TestHTTPS;
import junit.framework.TestCase;

public class TestWrapper extends TestCase {
	
	@Test
	public void testWrapperOnMain() throws Exception {
		TestHTTPS mytest = new TestHTTPS();
		mytest.run();
	}

}
