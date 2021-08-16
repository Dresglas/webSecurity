package com.sininenuni.websecurity.filter;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * @ClassName ParamsServletInputStream
 * @Description 还原请求参数
 * @Author 无涯
 * @Date 14:40 2019/09/27
 * @Version 1.0.0
 **/
public class ParamsServletInputStream extends ServletInputStream {

    private ByteArrayInputStream bis;

    public ParamsServletInputStream(ByteArrayInputStream bis) {
        this.bis = bis;
    }

    @Override
    public boolean isFinished() {
        return false;
    }

    @Override
    public boolean isReady() {
        return false;
    }

    @Override
    public void setReadListener(ReadListener listener) {

    }

    @Override
    public int read() throws IOException {
        return bis.read();
    }
}
