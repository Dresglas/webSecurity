package com.dresglas.websecurity.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;


@Configuration
public class CROSFilter {

    //此处可使用数据库配置，将域名白名单使用，分割用字符串存储
	String propertyInfo="www.baidu.com,www.wangyi.com";


	private static final Logger log = LoggerFactory.getLogger(CROSFilter.class);


	@Bean
	public FilterRegistrationBean corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true);
			if(null!=propertyInfo){
				String[] split = propertyInfo.split(",");
				for (String url:split) {
					config.addAllowedOrigin(url);
				}
			}else{
				config.addAllowedOrigin("*");
			}
		config.addAllowedHeader("*");
		config.addAllowedMethod("*");
		source.registerCorsConfiguration("/**", config);
		FilterRegistrationBean bean = new FilterRegistrationBean(new CorsFilter(source));
		bean.setOrder(0);
		return bean;
	}
}