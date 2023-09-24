package com.jp.dev.commons.security;

public class SecurityConstants {

    public static final String SECRET = "SECRET_KEY";
    public static final long EXPIRATION_TIME = 1800_000; // 30 min
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String SIGN_UP_URL = "/users";
    public static final String SIGN_UP_ADMIN_URL = "/users/admin";
    public static final String AUTH_URL = "/authenticate";
}
