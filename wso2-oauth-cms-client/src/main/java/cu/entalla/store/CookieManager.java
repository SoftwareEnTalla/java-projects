package cu.entalla.store;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.*;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

 @Getter
public class CookieManager {

    HttpServletResponse response;
    HttpServletRequest request;
    HttpSession session;
    private static CookieManager _instance;

    private CookieManager(){

    }
    private CookieManager updateState(){
        CookieManager._instance=this;
        return CookieManager._instance;
    }
    public CookieManager setRequest(HttpServletRequest request){

        if(request!=null){
            this.request=request;
            setSession(this.request.getSession());
        }
        return this;
    }
    public CookieManager setResponse(HttpServletResponse response){
        if(response!=null){
            this.response=response;
        }
        return this;
    }
     public CookieManager setSession(HttpSession session){
         this.session=session;
         return this;
    }
     public HttpSession getSession(){
         return this.session;
     }
    public static CookieManager getInstance(){
        if(CookieManager._instance==null)
            CookieManager._instance= new CookieManager();
        return CookieManager._instance.updateState();
    }
    public CookieManager addCookie(Cookie cookie){
        if(response!=null)
            response.addCookie(cookie);
        return updateState();
    }
    public CookieManager addCookie(String cookieName,String cookieValue,String uri,boolean isHttpOnly){
        if(response!=null){
            Cookie cookie = new Cookie(cookieName, cookieValue);
            cookie.setPath(uri);
            cookie.setHttpOnly(isHttpOnly);
            response.addCookie(cookie);
        }
        return updateState();
    }
    public CookieManager addCookie(String cookieName,String cookieValue,String uri,String comment,String domain,int expireIn,int version,boolean isHttpOnly,boolean isSecure){
        if(response!=null){
            Cookie cookie = new Cookie(cookieName, cookieValue);
            cookie.setPath(uri);
            cookie.setHttpOnly(isHttpOnly);
            cookie.setComment(comment);
            cookie.setDomain(domain);
            cookie.setSecure(isSecure);
            cookie.setMaxAge(expireIn);
            cookie.setVersion(version);
            response.addCookie(cookie);
        }
        return updateState();
    }
    public CookieManager setHeader(String headerName, String headerValue,boolean replace) {
        if(response!=null && headerName!=null && !headerName.isEmpty() && headerValue!=null && !headerValue.isEmpty()){
            if(!response.containsHeader(headerName) || response.containsHeader(headerName) && replace)
                response.setHeader(headerName,headerValue);
        }
        return updateState();
    }
    public CookieManager setHeader(String headerName, String headerValue) {
        return setHeader(headerName,headerValue,false);
    }
    public CookieManager setAttribute(String attributeName, Object attributeValue,boolean replace){
        if(request!=null && attributeName!=null && !attributeName.isEmpty()){
            Object attribute = request.getSession().getAttribute(attributeName);
            if(attribute==null || attribute!=null && replace)
                request.getSession().setAttribute(attributeName, attributeValue);
        }
        return updateState();
    }
    public CookieManager setAttribute(String attributeName, Object attributeValue){
        return setAttribute(attributeName,attributeValue,false);
    }

    public CookieManager sendRedirect(String location) throws IOException {
        if(response!=null)
          response.sendRedirect(location);
        return updateState();
    }

    public String getParameter(String parameterName) {
        return request.getParameter(parameterName);
    }

    public Object getAttribute(String attributeName) {
        Object attribute =request!=null? request.getSession().getAttribute(attributeName):null;
        return attribute!=null?attribute:null;
    }
    public boolean hasAttribute(String attributeName) {
        Object attribute =request!=null? request.getSession().getAttribute(attributeName):null;
        return attribute!=null;
    }

    public void sendError(int scInternalServerError, String message) throws IOException {
        if(response!=null)
         response.sendError(scInternalServerError, message);
    }

    public String getRequestURI() {
        return request!=null? request.getRequestURI():null;
    }

    public Map<String, String[]> getParameterMap() {
        return request!=null?request.getParameterMap():new HashMap<String,String[]>();
    }

     public String getMethod() {
        return request!=null?request.getMethod():null;
     }
 }
