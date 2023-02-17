package com.dresglas.websecurity.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * @ClassName requestUrlFilter
 * @Description 访问URL非法请求参数过滤器
 * @Author 无涯
 * @Date 10:33 2019/09/27
 * @Version 1.0.0
 **/
@WebFilter(urlPatterns = "/*", filterName = "XSSFilter")
public class XSSFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(XSSFilter.class);
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {


        XssHttpServletRequestWrapper xssRequest = new XssHttpServletRequestWrapper(
                (HttpServletRequest) request);
        chain.doFilter(xssRequest, response);
    }

    @Override
    public void destroy() {

    }
}
