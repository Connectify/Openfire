/**
 * $Revision$
 * $Date$
 *
 * Copyright (C) 2008 Jive Software. All rights reserved.
 *
 * This software is published under the terms of the GNU Public License (GPL),
 * a copy of which is included in this distribution.
 */
package org.jivesoftware.openfire.clearspace;

import org.jivesoftware.openfire.lockout.LockOutProvider;
import org.jivesoftware.openfire.lockout.LockOutFlag;
import org.jivesoftware.openfire.lockout.NotLockedOutException;
import org.jivesoftware.openfire.user.UserNotFoundException;
import static org.jivesoftware.openfire.clearspace.ClearspaceManager.HttpType.GET;
import static org.jivesoftware.openfire.clearspace.ClearspaceManager.HttpType.PUT;
import org.jivesoftware.util.Log;

import org.dom4j.Node;
import org.dom4j.Element;
import org.dom4j.Document;
import org.dom4j.DocumentHelper;

import java.util.List;

/**
 * The ClearspaceLockOutProvider uses the UserService web service inside of Clearspace
 * to retrieve user properties from Clearspace.  One of these properties refers to whether
 * the user is disabled or not.  In the future we may implement this in a different manner
 * that will require less overall communication with Clearspace.
 *
 * @author Daniel Henninger
 */
public class ClearspaceLockOutProvider implements LockOutProvider {

    protected static final String USER_URL_PREFIX = "userService/";

    private ClearspaceManager manager;

    /**
     * Generate a ClearspaceLockOutProvider instance.
     */
    public ClearspaceLockOutProvider() {
        // Gets the manager
        manager = ClearspaceManager.getInstance();
    }

    /**
     * The ClearspaceLockOutProvider will retrieve lockout information from Clearspace's user properties.
     * @see org.jivesoftware.openfire.lockout.LockOutProvider#getDisabledStatus(String)
     */
    public LockOutFlag getDisabledStatus(String username) throws NotLockedOutException {
        try {
            // Retrieve the disabled status, translate it into a LockOutFlag, and return it.
            return checkUserDisabled(getUserByUsername(username));
        }
        catch (UserNotFoundException e) {
            // Not a valid user?  We will leave it up to the user provider to handle rejecting this user.
            return null;
        }
    }

    /**
     * The ClearspaceLockOutProvider will set lockouts in Clearspace itself.
     * @see org.jivesoftware.openfire.lockout.LockOutProvider#setDisabledStatus(org.jivesoftware.openfire.lockout.LockOutFlag)
     */
    public void setDisabledStatus(LockOutFlag flag) {
        setEnabledStatus(flag.getUsername(), false);
    }

    /**
     * The ClearspaceLockOutProvider will set lockouts in Clearspace itself.
     * @see org.jivesoftware.openfire.lockout.LockOutProvider#unsetDisabledStatus(String)
     */
    public void unsetDisabledStatus(String username) {
        setEnabledStatus(username, true);
    }

    /**
     * The ClearspaceLockOutProvider will set lockouts in Clearspace itself.
     * @see org.jivesoftware.openfire.lockout.LockOutProvider#isReadOnly()
     */
    public boolean isReadOnly() {
        return false;
    }

    /**
     * Clearspace only supports a strict "are you disabled or not".
     * @see org.jivesoftware.openfire.lockout.LockOutProvider#isDelayedStartSupported()
     */
    public boolean isDelayedStartSupported() {
        return false;
    }

    /**
     * Clearspace only supports a strict "are you disabled or not".
     * @see org.jivesoftware.openfire.lockout.LockOutProvider#isTimeoutSupported()
     */
    public boolean isTimeoutSupported() {
        return false;
    }

    /**
     * Looks up and modifies a user's CS properties to indicate whether they are enabled or disabled.
     * It is important for this to incorporate the existing user data and only tweak the field
     * that we want to change.
     *
     * @param username Username of user to set status of.
     * @param enabled Whether the account should be enabled or disabled.
     */
    private void setEnabledStatus(String username, Boolean enabled) {
        try {
            Element user = getUserByUsername(username);
            Element modifiedUser = modifyUser(user.element("return"), "enabled", enabled ? "true" : "false");

            String path = USER_URL_PREFIX + "users";
            manager.executeRequest(PUT, path, modifiedUser.asXML());
        }
        catch (UserNotFoundException e) {
            Log.error("User with name " + username + " not found.", e);
        }
        catch (Exception e) {
            // It is not supported exception, wrap it into an UnsupportedOperationException
            throw new UnsupportedOperationException("Unexpected error", e);
        }
    }

    /**
     * Modifies user properties XML by replacing a particular attribute setting to something new.
     *
     * @param user User data XML.
     * @param attributeName Name of attribute to replace.
     * @param newValue New value for attribute.
     * @return Modified element.
     */
    private Element modifyUser(Element user, String attributeName, String newValue) {
        Document groupDoc =  DocumentHelper.createDocument();
        Element rootE = groupDoc.addElement("updateUser");
        Element newUser = rootE.addElement("user");
        List userAttributes = user.elements();
        for (Object userAttributeObj : userAttributes) {
            Element userAttribute = (Element)userAttributeObj;
            if (userAttribute.getName().equals(attributeName)) {
                newUser.addElement(userAttribute.getName()).setText(newValue);
            } else {
                newUser.addElement(userAttribute.getName()).setText(userAttribute.getText());
            }
        }
        return rootE;
    }

    /**
     * Examines the XML returned about a user to find out if they are enabled or disabled, throwing
     * a NotLockedOutException if they are.
     *
     * @param responseNode Element returned from REST service. (@see #getUserByUsername)
     * @return Either a LockOutFlag indicating that the user is disabled, or an exception is thrown.
     * @throws NotLockedOutException if the user is not currently locked out.
     */
    private LockOutFlag checkUserDisabled(Node responseNode) throws NotLockedOutException {
        try {
            Node userNode = responseNode.selectSingleNode("return");

            // Gets the username
            String username = userNode.selectSingleNode("username").getText();

            // Gets the enabled field
            boolean isEnabled = Boolean.valueOf(userNode.selectSingleNode("enabled").getText());
            if (isEnabled) {
                // We're good, indicate that they're not locked out.
                throw new NotLockedOutException();
            }
            else {
                // Creates the lock out flag
                return new LockOutFlag(username, null, null);
            }
        }
        catch (Exception e) {
            // Hrm.  This is not good.  We have to opt on the side of positive.
            Log.error("Error while looking up user's disabled status from Clearspace: ", e);
            throw new NotLockedOutException();
        }
    }

    /**
     * Retrieves user properties for a Clearspace user in XML format.
     *
     * @param username Username to look up.
     * @return XML Element including information about the user.
     * @throws UserNotFoundException The user was not found in the Clearspace database.
     */
    private Element getUserByUsername(String username) throws UserNotFoundException {
        try {
            // Requests the user
            String path = USER_URL_PREFIX + "users/" + username;
            // return the response
            return manager.executeRequest(GET, path);
        }
        catch (Exception e) {
            // It is not supported exception, wrap it into an UserNotFoundException
            throw new UserNotFoundException("Error loading the user from Clearspace: ", e);
        }
    }

}
