/**
 *
 * Copyright (C) 2008 Jive Software. All rights reserved.
 *
 * This software is published under the terms of the GNU Public License (GPL),
 * a copy of which is included in this distribution, or a commercial license
 * agreement with Jive.
 */

package org.jivesoftware.openfire.plugin;

import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.jivesoftware.openfire.auth.DefaultAuthProvider;
import org.jivesoftware.openfire.auth.JDBCAuthProvider;
import org.jivesoftware.openfire.auth.UnauthorizedException;

/**
 * The JDBC auth provider allows you to authenticate users against any database
 * that you can connect to with JDBC. It can be used along with the
 * {@link HybridAuthProvider hybrid} auth provider, so that you can also have
 * XMPP-only users that won't pollute your external data.<p>
 *
 * To enable this provider, set the following in the system properties:
 * <ul>
 * <li><tt>provider.auth.className = org.jivesoftware.openfire.plugin.SaltingJDBCAuthProvider</tt>
 * </ul>
 *
 * You'll also need to set your JDBC driver, connection string, and SQL statements:
 *
 * <ul>
 * <li><tt>jdbcProvider.driver = com.mysql.jdbc.Driver</tt></li>
 * <li><tt>jdbcProvider.connectionString = jdbc:mysql://localhost/dbname?user=username&amp;password=secret</tt></li>
 * <li><tt>jdbcAuthProvider.passwordSQL = SELECT password FROM user_account WHERE username=?</tt></li>
 * <li><tt>jdbcAuthProvider.passwordType = plain</tt></li>
 * <li><tt>jdbcAuthProvider.allowUpdate = true</tt></li>
 * <li><tt>jdbcAuthProvider.setPasswordSQL = UPDATE user_account SET password=? WHERE username=?</tt></li>
 * </ul>
 *
 * <ul>
 * <li><tt>extJdbcAuthProvider.multiSource = true</tt></li>
 * </ul>
 *
 * The multiSource setting tells Openfire if the user credentials should checked against
 * the normal user database, if the check against the external database failed. Setting
 * the value is optional (when not set, it defaults to "false").
 *
 * @author CSchulz (http://community.igniterealtime.org/people/CSchulz)
 */
public class ExtendedJDBCAuthProvider extends JDBCAuthProvider {
	private static final Logger Log = LoggerFactory.getLogger(ExtendedJDBCAuthProvider.class);
	
    private boolean multiSource;

    /**
     * Constructs a new JDBC authentication provider.
     */
    public ExtendedJDBCAuthProvider() {
    	super();
    	JiveGlobals.migrateProperty("extJdbcAuthProvider.multiSource");

    	multiSource = JiveGlobals.getBooleanProperty("extJdbcAuthProvider.multiSource", false);
    	Log.debug("Use following multiSource "+multiSource);
    }

    public void authenticate(String username, String password, String saltedPassword) throws UnauthorizedException {
    	try {
			super.authenticate(username, saltedPassword);
		} catch (UnauthorizedException e) {
			if (multiSource) {
				Log.info("Authenticating over JDBCAuthProvider failed, trying the normal way now.");
				DefaultAuthProvider dap = new DefaultAuthProvider();
				dap.authenticate(username, password);
			} else
			{
				throw e;
			}
		}
    }
}
