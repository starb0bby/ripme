package com.rarchives.ripme.utils;

import org.apache.http.protocol.HttpContext;

public class User {

    public String username;
    public String password;
    public String vb_security_token;
    public HttpContext httpContext;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
        vb_security_token = new String();
    }

    public User() {
        this.username = new String();
        this.password = new String();
        this.vb_security_token = new String();
    }
}
