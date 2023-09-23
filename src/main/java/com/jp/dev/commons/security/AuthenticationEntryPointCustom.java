package com.jp.dev.commons.security;

import com.jp.dev.commons.exceptions.ExceptionResponse;
import com.jp.dev.commons.utils.JsonParser;
import java.io.IOException;
import java.util.Objects;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

public class AuthenticationEntryPointCustom implements AuthenticationEntryPoint {

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException authException) throws IOException {

    response.setContentType("application/json;charset=UTF-8");

    final String expired = (String) request.getAttribute("expired");

    if (Objects.nonNull(expired)) {
      response.setStatus(HttpServletResponse.SC_FORBIDDEN);
      response
          .getWriter().write(JsonParser.toJson(new ExceptionResponse("token expired", expired)));
    } else {
      response.getWriter()
          .write(JsonParser
              .toJson(new ExceptionResponse("Invalid Login details", authException.getMessage())));
    }
  }
}
