/**
 * $Revision: 1116 $
 * $Date: 2005-03-10 20:18:08 -0300 (Thu, 10 Mar 2005) $
 *
 * Copyright (C) 2008 Jive Software. All rights reserved.
 *
 * This software is published under the terms of the GNU Public License (GPL),
 * a copy of which is included in this distribution, or a commercial license
 * agreement with Jive.
 */

package org.jivesoftware.openfire.auth;

import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The JDBC auth provider allows you to authenticate users against any database
 * that you can connect to with JDBC. It can be used along with the
 * {@link HybridAuthProvider hybrid} auth provider, so that you can also have
 * XMPP-only users that won't pollute your external data.<p>
 *
 * To enable this provider, set the following in the XML configuration file:
 *
 * <pre>
 * &lt;provider&gt;
 *     &lt;auth&gt;
 *         &lt;className&gt;org.jivesoftware.openfire.auth.SaltingJDBCAuthProvider&lt;/className&gt;
 *     &lt;/auth&gt;
 * &lt;/provider&gt;
 * </pre>
 *
 * You'll also need to set your JDBC driver, connection string, and SQL statements:
 *
 * <pre>
 * &lt;jdbcProvider&gt;
 *     &lt;driver&gt;com.mysql.jdbc.Driver&lt;/driver&gt;
 *     &lt;connectionString&gt;jdbc:mysql://localhost/dbname?user=username&amp;password=secret&lt;/connectionString&gt;
 * &lt;/jdbcProvider&gt;
 *
 * &lt;JdbcAuthProvider&gt;
 *      &lt;passwordSQL&gt;SELECT password FROM user_account WHERE username=?&lt;/passwordSQL&gt;
 *      &lt;passwordType&gt;plain&lt;/passwordType&gt;
 * &lt;/JdbcAuthProvider&gt;
 * 
 * &lt;extJdbcAuthProvider&gt;
 *      &lt;multiSource&gt;true&lt;/multiSource&gt;
 * &lt;/extJdbcAuthProvider&gt;</pre>
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
