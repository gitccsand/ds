<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Insert title here</title>

<script type="text/javascript">
function getCookieValue(c_name){
if (document.cookie.length>0){
c_start=document.cookie.indexOf(c_name + "=")
if (c_start!=-1){
c_start=c_start + c_name.length+1
c_end=document.cookie.indexOf(";",c_start)
if (c_end==-1) c_end=document.cookie.length
return unescape(document.cookie.substring(c_start,c_end))
}
}
return ""
};
</script>

</head>
<body>


cookie value from http servlet<br>
(username cookie is set to httponly):
<br>
<br>
cookie username: <%=session.getAttribute("username") %>
<br>
cookie lastTime: <%=session.getAttribute("lastTime") %>
<p>
<p>
cookie value from javascript<br>
(username cookie is set to httponly):
<p>
<script type="text/javascript">
    document.write("cookie username: ",getCookieValue("username"),"<br>");
    document.write("cookie lastTime: ",getCookieValue("lastTime"),"<br>");
    if (document.cookie=="") {
        document.write("no cookie");
    } else {       
        document.write("cookie content:","<br>");
        document.write(document.cookie,"<br>");
    }
 
</script>


</body>
</html>