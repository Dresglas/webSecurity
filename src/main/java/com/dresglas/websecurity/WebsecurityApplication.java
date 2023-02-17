package com.dresglas.websecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.web.servlet.ServletComponentScan;
import org.springframework.cache.annotation.EnableCaching;

@ServletComponentScan("com.dresglas.websecurity.filter")
@EnableCaching //开启缓存
@SpringBootApplication(exclude={DataSourceAutoConfiguration.class, HibernateJpaAutoConfiguration.class})
public class WebsecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run( WebsecurityApplication.class, args );
    }

}
