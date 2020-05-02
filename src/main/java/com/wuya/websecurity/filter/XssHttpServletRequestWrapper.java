package com.wuya.websecurity.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

public class XssHttpServletRequestWrapper extends HttpServletRequestWrapper{

    HttpServletRequest orgRequest = null;

    private Map<String, String[]> params = new HashMap<>();
    private static final String ENCODING = "UTF-8";
    private static final String CLASSTYPE = "java.lang.String";
    private static final String JSONGTYPE="com.alibaba.fastjson.JSONObject";
    /**
     * @param request
     */
    public XssHttpServletRequestWrapper(HttpServletRequest request) {
        super(request);
        Map<String, String[]> requestMap = request.getParameterMap();
        //System.out.println("转化前参数：" + JSON.toJSONString(requestMap));
        this.params.putAll(requestMap);
        this.modifyParameters();
        //System.out.println("转化后参数：" + JSON.toJSONString(params));
        orgRequest = request;
    }

    /**
     * 重写getInputStream方法  post请求参数必须通过流才能获取到值
     */
    @Override
    public ServletInputStream getInputStream() throws IOException {

        ServletInputStream stream = super.getInputStream();

        //非json类型，直接返回
        if (!super.getHeader(HttpHeaders.CONTENT_TYPE).contains(MediaType.APPLICATION_JSON_VALUE)) {
            return stream;
        }
        String json = IOUtils.toString(stream, ENCODING);

        if (StringUtils.isBlank(json)) {
            return stream;
        }

        //System.out.println("转化前参数：" + json);
        Map<String, Object> map = modifyParams(json);
        //System.out.println("转化后参数：" + JSON.toJSONString(map));

        ByteArrayInputStream bis = new ByteArrayInputStream(JSON.toJSONString(map).getBytes(ENCODING));

        return new ParamsServletInputStream(bis);
    }



    private static Map<String, Object> modifyParams(String json) {

        Map<String, Object> params = JSON.parseObject(json);
        Map<String, Object> maps = new HashMap<>(params.size());
        for (String key : params.keySet()) {
            Object value = getValue(params.get(key));
            maps.put(key, value);
        }
        return maps;
    }

    /**
     * 将parameter的值去除空格后重写回去
     */
    private void modifyParameters() {
        Set<String> set = params.keySet();
        Iterator<String> it = set.iterator();
        while (it.hasNext()) {
            String key = (String) it.next();
            String[] values = params.get(key);
            values[0] = values[0].trim();
            params.put(key, values);
        }
    }
    private static Object getValue(Object obj) {

        if (obj == null) {
            return null;
        }
        String type = obj.getClass().getName();
        // 对字符串的处理
        if (CLASSTYPE.equals(type)) {
            obj = obj.toString().trim();
            obj=xssEncode(obj.toString());
        }else if(JSONGTYPE.equals(type)){
            obj=xssEncode(JSONObject.toJSONString(obj));
            obj = net.sf.json.JSONObject.fromObject(obj);
        }
        return obj;
    }

    /**
     * 覆盖getParameter方法，将参数名和参数值都做xss过滤。<br/>
     * 如果需要获得原始的值，则通过super.getParameterValues(name)来获取<br/>
     * getParameterNames,getParameterValues和getParameterMap也可能需要覆盖
     */
    public String getParameter(String name) {
        String value = super.getParameter(xssEncode(name));
        if (value != null) {
            value = xssEncode(value);

        }
        return value;
    }

    /**
     * 覆盖getHeader方法，将参数名和参数值都做xss过滤。<br/>
     * 如果需要获得原始的值，则通过super.getHeaders(name)来获取<br/> getHeaderNames 也可能需要覆盖
     */
    public String getHeader(String name) {

        String value = super.getHeader(xssEncode(name));
        if (value != null) {
            value = xssEncode(value);
        }
        return value;

    }

    /**
     * 将容易引起xss漏洞的半角字符直接替换成全角字符
     *
     * @param s
     * @return
     */
    private static String xssEncode(String s) {
        if (s == null || "".equals(s.trim())) {
            return s;
        }
        return filter(s);
    }

    public static String filter(String message) {

        if (message == null)
            return (null);
        message = message.replaceAll("<(?i)script(.*)>", "");
        message = message.replaceAll("</(?i)script(.*)>", "");
        message = message.replaceAll("(?i)alert(.*)", "");
        message = message.replaceAll("eval\\((.*)\\)", "");
        message = message.replaceAll("[\"'][\\s]*javascript:(.*)[\"']", "");
        message = message.replaceAll("[\"'][\\s]*script:(.*)[\"']", "");
        message = message.replaceAll("\\./", "");//防止路径递归漏洞

        char content[] = new char[message.length()];
        message.getChars(0, message.length(), content, 0);
        StringBuffer result = new StringBuffer(content.length + 50);
        for (int i = 0; i < content.length; i++) {
            switch (content[i]) {
                case '<':
                    result.append("&lt;");
                    break;
                case '>':
                    result.append("&gt;");
                    break;
			/*case '&':
				result.append("&amp;");
				break;*/
//			case '"':
//				result.append("&quot;");
//				break;
                case ';':
                    result.append("");
                    break;
//			case '$':
//				result.append("&#36;");
//				break;
//			case '%':
//				result.append("&#37;");
//				break;
//			case '@':
//				result.append("&#64;");
//				break;
                case '\'':
                    result.append("&#39;");
                    break;
                case '(':
                    result.append("&#40;");
                    break;
                case ')':
                    result.append("&#41;");
                    break;
//			case '+':
//				result.append("&#43;");
//				break;
                case '\r':
                    result.append("&#13;");
                    break;
                case '\n':
                    result.append("&#10;");
                    break;
//			case '\\':
//				result.append("");
//				break;
                //end
                default:
                    result.append(content[i]);
                    break;
            }
        }
        return (result.toString());

    }

    /**
     * 获取最原始的request
     *
     * @return
     */
    public HttpServletRequest getOrgRequest() {
        return orgRequest;
    }

    /**
     * 获取最原始的request的静态方法
     *
     * @return
     */
    public static HttpServletRequest getOrgRequest(HttpServletRequest req) {
        if (req instanceof XssHttpServletRequestWrapper) {
            return ((XssHttpServletRequestWrapper) req).getOrgRequest();
        }

        return req;
    }
}
