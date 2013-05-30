<%@ page import="org.jivesoftware.openfire.plugin.gojara.permissions.TransportSessionManager"%>
<%@ page import="org.jivesoftware.openfire.plugin.gojara.database.SessionEntry" %>
<%@ page import="java.util.Map"%>
<%@ page import="java.util.HashMap"%>
<%@ page import="java.util.Set"%>
<%@ page import="java.util.Date"%>
<%@ page import="java.util.ArrayList" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jstl/core" %>
<%  
	TransportSessionManager transportManager = TransportSessionManager.getInstance();
	int current_page;
	int current_limit;
	//Helper object for restraining sorting to existing colums and nice generation of sorting links
	Map<String, String> sortParams = new HashMap<String, String>();
	if (request.getParameter("sortby") != null && request.getParameter("sortorder") != null) {
		// pr�fen wenn ok, nehmen wir die, ansonsten
		String allowedAttr = "username transport lastActivity";
		String allowedOrder = "ASC DESC";
		String sortAttr = request.getParameter("sortby");
		String sortOrder = request.getParameter("sortorder");
		if (allowedAttr.contains(sortAttr) && allowedOrder.contains(sortOrder)) {
			sortParams.put("sortby", sortAttr);
			sortParams.put("sortorder", sortOrder);
		}
	} else {
		sortParams.put("sortby", "username");
		sortParams.put("sortorder", "ASC");
	}
	
	//pagination
	if (request.getParameter("page") == null) {
		current_page = 1;
	} else {
		try {
			current_page = Integer.parseInt(request.getParameter("page"));
		} catch (Exception e){
			current_page = 1;
		}
	}
	if (request.getParameter("limit") == null) {
		current_limit = 15;
	} else {
		try {
			current_limit= Integer.parseInt(request.getParameter("limit"));
			if (current_limit > 1000) { current_limit = 1000; }
		} catch (Exception e){
			current_limit = 15;
		}
	}
	%>
<%! 
	public String sortingHelper(String column, Map<String, String> sortParams) {
		String image_asc = "<img alt=\"sorted ASC\" src=\"/images/sort_ascending.gif\">";
		String image_desc = "<img alt=\"sorted DESC\" src=\"/images/sort_descending.gif\">";
		String link_beginning = "<a href=\"gojara-RegistrationsOverview.jsp?sortby=";
		String ending = (column.equals("username") ? "User Name:" : column.equals("transport") ? "Resource:" : "Last Login was at:") + "</a>";
		
		String sortinglink = "";
		if (sortParams.containsValue(column)) {
			if (sortParams.containsValue("ASC")) {
				sortinglink = image_asc + link_beginning + column + "&sortorder=DESC\">" + ending;
			} else if (sortParams.containsValue("DESC")) {
				sortinglink = image_desc + link_beginning + column + "&sortorder=ASC\">" + ending;
			}
		} else {
			// This is not the currently sorted colum so we want to sort with it, Ascending.
			sortinglink = link_beginning + column + "&sortorder=ASC\">" + ending;
		}
		return sortinglink;
 	}
%>
 <html>
   <head>
       <title>Overview of existing Registrations</title>
       <meta name="pageID" content="gojaraRegistrationAdministration"/>
   </head>
   <body>
	<%	
		//do unregisters if supplied
		if (request.getParameterMap() != null) {
			String uninteresting_params = "sortorder sortby page limit";
			for (Object key : request.getParameterMap().keySet()) {
				if (uninteresting_params.contains(key.toString())) {
					continue;
				}
				String[] uservalues = request.getParameterValues(key.toString());
				for (String transport : uservalues) { %>
					<ul>			
					<%= transportManager.removeRegistrationOfUser(transport, key.toString())%>
					</ul>
				<% } %>
		<% } %>
	<% } %>
   <%= current_page %>
   <%= current_limit %>
   <h1>For Loop in JSTL</h1>
	<c:forEach var="i" begin="1" end="20" step="1" varStatus ="status">
	<c:out value="${i}" /> 
	</c:forEach>
	<h6>Logintime 1970 means User did only register but never logged in, propably because of invalid credentials.</h6>
	<form name="unregister-form" id="gojara-RegOverviewUnregister"method="POST">
	<div class="jive-table">
		<table cellpadding="0" cellspacing="0" border="0" width="100%">
			<thead>
				<tr>
					<th nowrap><%= sortingHelper("username",sortParams) %></th>
					<th nowrap><%= sortingHelper("transport",sortParams) %></th>
					<th nowrap>Resource active?</th>
					<th nowrap><%= sortingHelper("lastActivity",sortParams) %></th>
					<th nowrap>Unregister?</th>
				</tr>
			</thead>
			<tbody>
				<% 
				//Here we do our nice query
				ArrayList<SessionEntry> registrations = transportManager.getAllRegistrations(sortParams.get("sortby"), sortParams.get("sortorder")); 
				%>
				<% for (SessionEntry registration : registrations) { %>
				<tr class="jive-odd">
					<td><a href="gojara-sessionDetails.jsp?username=<%=registration.getUsername()%>"><%= registration.getUsername()%></a></td>
					<td><%= registration.getTransport()%></td>
					<td>
					<% if (transportManager.isTransportActive(registration.getTransport())) { %>
						<img alt="Yes" src="/images/success-16x16.gif">
					<% } else { %>
						<img alt="No" src="/images/error-16x16.gif">
					<% } %></td>
					<td><%= registration.getLast_activityAsDate()%></td>
					<td><input type="checkbox" name="<%= registration.getUsername() %>" value="<%= registration.getTransport() %>"></td>
				</tr>
				<% } %>
			</tbody>
		</table>
	</div>
	<br>
	<center><input type="submit" value="Unregister"></center>
	</form>
   </body>
   </html>