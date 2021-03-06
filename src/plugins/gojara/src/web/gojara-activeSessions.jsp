<%@ page
	import="org.jivesoftware.openfire.plugin.gojara.sessions.TransportSessionManager"%>
<%@ page
	import="org.jivesoftware.openfire.plugin.gojara.sessions.GojaraAdminManager"%>

<%@ page
	import="org.jivesoftware.openfire.plugin.gojara.sessions.GatewaySession"%>
<%@ page
	import="org.jivesoftware.openfire.plugin.gojara.utils.JspHelper"%>
<%@ page import="java.util.Map"%>
<%@ page import="java.util.HashMap"%>
<%@ page import="java.util.Set"%>
<%@ page import="java.util.Date"%>
<%@ page import="java.util.ArrayList"%>

<%
	TransportSessionManager transportManager = TransportSessionManager.getInstance();
	GojaraAdminManager gojaraAdminManager = GojaraAdminManager.getInstance();
	//Helper object for generation of sorting links, column restriction is done in DatabaseManager
	Map<String, String> sortParams = new HashMap<String, String>();
	if (request.getParameter("sortby") != null && request.getParameter("sortorder") != null) {
		sortParams.put("sortby", request.getParameter("sortby"));
		sortParams.put("sortorder", request.getParameter("sortorder"));
	} else {
		sortParams.put("sortby", "transport");
		sortParams.put("sortorder", "ASC");
	}

	//pagination
	int current_page = 1;
%>
<html>
<head>
<title>Gateway Sessions</title>

<meta name="pageID" content="gojaraSessions" />
</head>
<body>
	 <div align="center">
	<% if (!gojaraAdminManager.areGatewaysConfigured()) {%>
		<h2><a href="gojara-gatewayStatistics.jsp">Warning: Not all Gateways are configured for admin usage. This means session details may be inaccurate or not logged at all.<br/>
		 Please configure admin_jid = gojaraadmin@yourdomain in Spectrum2 transport configuration.</a></h2><br/>
	 <% } %>
	<h4>
		Current number of active Gateway Sessions: &emsp;
		<b style="font-size:150%"><%= transportManager.getNumberOfActiveSessions() %></b>
	</h4>
	<br>
	<%
		Map<String, Map<String, Long>> sessions = transportManager.getSessions();
		for (String transport : sessions.keySet()) {
	%>
	<%=transport.substring(0, 10)%>... :
	<b style="font-size:150%"><%=sessions.get(transport).size()%></b> &emsp;
	<%
		}
	%></div>
	<br>
	<br>
	<%
		ArrayList<GatewaySession> gwSessions = transportManager
				.getSessionsSorted(sortParams.get("sortby"), sortParams.get("sortorder"));
		int numOfSessions = gwSessions.size();
		int numOfPages = numOfSessions / 100;
		if (request.getParameter("page") != null) {
			//lets check for validity
			try {
				current_page = Integer.parseInt(request.getParameter("page"));
				if (current_page < 1 || current_page > (numOfPages))
					current_page = 1;
			} catch (Exception e) {
			}
		}
		// we now know current_page is in valid range, so set it for computation
		current_page -= 1;
		numOfPages += 1;
		int next_items = (current_page * 100) + 99;
		if (next_items > numOfSessions)
			next_items = numOfSessions;
	%>
	<p>
		Pages: [
		<%
		for (int i = 1; i <= numOfPages; i++) {
	%>
		<%="<a href=\"gojara-activeSessions.jsp?page=" + i + "&sortby=" + sortParams.get("sortby") + "&sortorder="
						+ sortParams.get("sortorder") + "\" class=\"" + ((current_page + 1) == i ? "jive-current" : "") + "\">" + i
						+ "</a>"%>
		<%
			}
		%>
		]
	</p>
	<div class="jive-table">
		<table cellpadding="0" cellspacing="0" border="0" width="100%">
			<thead>
				<tr>
					<th nowrap><%=JspHelper.sortingHelperSessions("username", sortParams)%></th>
					<th nowrap><%=JspHelper.sortingHelperSessions("transport", sortParams)%></th>
					<th nowrap><%=JspHelper.sortingHelperSessions("loginTime", sortParams)%></th>
				</tr>
			</thead>
			<tbody>
				<%
					for (GatewaySession gwsession : gwSessions.subList(current_page * 100, next_items)) {
				%>
				<tr class="jive-odd">
					<td><a
						href="gojara-sessionDetails.jsp?username=<%=gwsession.getUsername()%>"
						title="Session Details for <%=gwsession.getUsername()%>"><%=gwsession.getUsername()%></a></td>
					<td><%=gwsession.getTransport()%></td>
					<td
						title="<%=JspHelper.dateDifferenceHelper(gwsession.getLastActivity())%>"><%=gwsession.getLastActivity()%></td>
				</tr>
				<%
					}
				%>
			</tbody>
		</table>
	</div>
	<br>
	<p>
		Pages: [
		<%
		for (int i = 1; i <= numOfPages; i++) {
	%>
		<%="<a href=\"gojara-activeSessions.jsp?page=" + i + "&sortby=" + sortParams.get("sortby") + "&sortorder="
						+ sortParams.get("sortorder") + "\" class=\"" + ((current_page + 1) == i ? "jive-current" : "") + "\">" + i
						+ "</a>"%>
		<%
			}
		%>
		]
	</p>
</body>
</html>