/**
 *
 * Copyright (C) 2008 Jive Software. All rights reserved.
 *
 * This software is published under the terms of the GNU Public License (GPL),
 * a copy of which is included in this distribution, or a commercial license
 * agreement with Jive.
 */

package org.jivesoftware.openfire.plugin;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.jivesoftware.openfire.auth.DefaultAuthProvider;
import org.jivesoftware.openfire.auth.JDBCAuthProvider;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.database.DbConnectionManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.StringUtils;
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
 * <ul>
 *  <li><tt>provider.auth.className = org.jivesoftware.openfire.plugin.SaltingJDBCAuthProvider</tt>
 * </ul>
 *
 * You'll also need to set your JDBC driver, connection string, and SQL statements:
 *
 * <ul>
 * <li><tt>jdbcProvider.driver = com.mysql.jdbc.Driver</tt></li>
 * <li><tt>jdbcProvider.connectionString = jdbc:mysql://localhost/dbname?user=username&amp;password=secret</tt></li>
 * <li><tt>jdbcAuthProvider.passwordSQL = SELECT password FROM user_account WHERE username=?</tt></li>
 * <li><tt>jdbcAuthProvider.passwordType = plain</tt></li>
 * <li><tt>saltJdbcAuthProvider.saltSQL = SELECT salt FROM user_account WHERE username=?</tt></li>
 * <li><tt>saltJdbcAuthProvider.saltPosition = before</tt></li>
 * <li><tt>saltJdbcAuthProvider.doubleHashed = true</tt></li>
 * </ul>
 *
 * The saltSQL setting tells Openfire where to find the salt. Setting the value is optional
 * (when not set, the salting won't work). Here an example:
 * SELECT salt FROM user_account WHERE username=?
 * 
 * The saltPosition setting tells Openfire how the password is salted. Setting the value
 * is optional (when not set, it defaults to "none"). The valid values are:<ul>
 *      <li>{@link SaltPosition#none none}
 *      <li>{@link SaltPosition#before before}
 *      <li>{@link SaltPosition#after after}
 *  </ul>
 *  
 * The doubleHashed setting tells Openfire if the password should be hashed before salting.
 * Setting the value is optional (when not set, it defaults to "true").
 *
 * @author David Snopek
 * @editor CSchulz (http://community.igniterealtime.org/people/CSchulz)
 */
public class SaltingJDBCAuthProvider extends ExtendedJDBCAuthProvider {
	private static final Logger Log = LoggerFactory.getLogger(SaltingJDBCAuthProvider.class);
	
    private String connectionString;
    private String saltSQL;
    private JDBCAuthProvider.PasswordType passwordType;
    private SaltPosition saltPosition;
    private boolean doubleHashed;

    /**
     * Constructs a new JDBC authentication provider.
     */
    public SaltingJDBCAuthProvider() {
    	super();
    	JiveGlobals.migrateProperty("saltJdbcAuthProvider.saltSQL");
    	JiveGlobals.migrateProperty("saltJdbcAuthProvider.saltPosition");
    	JiveGlobals.migrateProperty("saltJdbcAuthProvider.doubleHashed");
    	
    	// Load the JDBC driver and connection string.
    	String jdbcDriver = JiveGlobals.getProperty("jdbcProvider.driver");
    	Log.debug("Use following driver "+jdbcDriver);
    	
        try {
            Class.forName(jdbcDriver).newInstance();
        }
        catch (Exception e) {
            Log.error("Unable to load JDBC driver: " + jdbcDriver, e);
            return;
        }

        connectionString = JiveGlobals.getProperty("jdbcProvider.connectionString");
    	Log.debug("Use following connectionString "+connectionString);

        // Load SQL statements.
        saltSQL = JiveGlobals.getProperty("saltJdbcAuthProvider.saltSQL");
    	Log.debug("Use following saltSQL "+saltSQL);
    	
        passwordType = JDBCAuthProvider.PasswordType.plain;
        try {
            passwordType = JDBCAuthProvider.PasswordType.valueOf(
                    JiveGlobals.getProperty("jdbcAuthProvider.passwordType", "plain"));
        }
        catch (IllegalArgumentException iae) {
            Log.error("Error while parsing the passwordType", iae);
        }
    	Log.debug("Use following passwordType "+passwordType);
        
        saltPosition = SaltPosition.none;
        try {
        	saltPosition = SaltPosition.valueOf(
                    JiveGlobals.getProperty("saltJdbcAuthProvider.saltPosition", "none"));
        }
        catch (IllegalArgumentException iae) {
        	Log.error("Error while parsing the saltPosition", iae);
        }
    	Log.debug("Use following saltPosition "+saltPosition);
    	
    	doubleHashed = JiveGlobals.getBooleanProperty("saltJdbcAuthProvider.doubleHashed", true);
    	Log.debug("Use following doubleHashed "+doubleHashed);
    }

    public void authenticate(String username, String password) throws UnauthorizedException {
    	Log.info("Trying to authenticate ...");
        if (username == null || password == null) {
            throw new UnauthorizedException();
        }
        username = username.trim().toLowerCase();
        if (username.contains("@")) {
            // Check that the specified domain matches the server's domain
            int index = username.indexOf("@");
            String domain = username.substring(index + 1);
            if (domain.equals(XMPPServer.getInstance().getServerInfo().getXMPPDomain())) {
                username = username.substring(0, index);
            } else {
                // Unknown domain. Return authentication failed.
                throw new UnauthorizedException();
            }
        }
        
        String userPassword = password;
        try {
        	if (saltPosition != SaltPosition.none) {
            	Log.debug("Trying to authenticate with salting ...");
            	
            	if (doubleHashed) {
	                if (passwordType == JDBCAuthProvider.PasswordType.md5) {
	                	userPassword = StringUtils.hash(userPassword, "MD5");
	                } else if (passwordType == JDBCAuthProvider.PasswordType.sha1) {
	                	userPassword = StringUtils.hash(userPassword, "SHA-1");
	                } else if (passwordType == JDBCAuthProvider.PasswordType.sha256) {
	                	userPassword = StringUtils.hash(userPassword, "SHA-256");
	                } else if (passwordType == JDBCAuthProvider.PasswordType.sha512) {
	                	userPassword = StringUtils.hash(userPassword, "SHA-512");
	                }
            	}
            	
            	String salt = getSaltValue(username);
            	if (saltPosition == SaltPosition.before) {
            		userPassword = salt + userPassword;
            	} else
            	{
            		userPassword += salt;
            	}
            } else
            {
            	Log.debug("Trying to authenticate without salting ...");
            }
        }
        catch (UserNotFoundException unfe) {
            Log.info("Could not find salt for user "+username);
        }
        
        super.authenticate(username, password, userPassword);
    }

    public void setPassword(String username, String password)
            throws UserNotFoundException, UnsupportedOperationException
    {
        throw new UnsupportedOperationException();
    }

    /**
     * Returns the value of the password field. It will be in plain text or hashed
     * format, depending on the password type.
     *
     * @return the password value.
     * @throws UserNotFoundException if the given user could not be loaded.
     */
    private String getSaltValue(String username) throws UserNotFoundException {
        String salt = null;
        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            con = DriverManager.getConnection(connectionString);
            pstmt = con.prepareStatement(saltSQL);
            pstmt.setString(1, username);

            rs = pstmt.executeQuery();

            // If the query had no results, the username and password
            // did not match a user record. Therefore, throw an exception.
            if (!rs.next()) {
                throw new UserNotFoundException();
            }

            salt = rs.getString(1);
        }
        catch (SQLException e) {
            Log.error("Exception in JDBCAuthProvider", e);
            throw new UserNotFoundException();
        }
        finally {
            DbConnectionManager.closeConnection(rs, pstmt, con);
        }
        
        return salt;
    }
    
    public enum SaltPosition {
        /**
         * Salting is disabled.
         */
    	none,
        /**
         * The salt is in front of the password.
         */
    	before,
        /**
         * The salt is after the password.
         */
    	after;
    }
}
