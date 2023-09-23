package com.jp.dev.commons.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.jp.dev.commons.exceptions.ForbiddenException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class TokenUtils {

  public static String getRole(String token) {

    try {
      token = token.replace("Bearer", "");

      return JWT.decode(token).getClaim("role").asString();
    } catch (JWTDecodeException exception) {
      Logger.getLogger(TokenUtils.class.getName())
          .log(Level.SEVERE, exception, () -> "Error parsing JWT");
      throw new ForbiddenException("Invalid JWT Token");
    }
  }

  public static String getSub(String token) {

    try {
      token = token.replace("Bearer", "");

      return JWT.decode(token).getSubject();
    } catch (JWTDecodeException exception) {
      Logger.getLogger(TokenUtils.class.getName())
          .log(Level.SEVERE, exception, () -> "Error parsing JWT");
      throw new ForbiddenException("Invalid JWT Token");
    }
  }
}
