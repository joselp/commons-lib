package com.jp.dev.commons.security;

import static com.jp.dev.commons.security.SecurityConstants.SECRET;
import static com.jp.dev.commons.security.SecurityConstants.TOKEN_PREFIX;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public JWTAuthorizationFilter(AuthenticationManager authManager) {
        super(authManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        String jwtToken = req.getHeader(AUTHORIZATION);

        if (jwtToken == null || !jwtToken.startsWith(TOKEN_PREFIX)) {
            res.setStatus(HttpStatus.UNAUTHORIZED.value());
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = validateTokenJwt(req);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    // Reads the JWT from the Authorization header, and then uses JWT to validate the token
    private UsernamePasswordAuthenticationToken validateTokenJwt(HttpServletRequest request) {
        String jwtToken = request.getHeader(AUTHORIZATION);

        if (jwtToken != null) {
            // parse the jwtToken.
            try {
                String user = JWT.require(Algorithm.HMAC512(SECRET.getBytes()))
                    .build()
                    .verify(jwtToken.replace(TOKEN_PREFIX, ""))
                    .getSubject();

                String role = JWT.require(Algorithm.HMAC512(SECRET.getBytes()))
                    .build()
                    .verify(jwtToken.replace(TOKEN_PREFIX, ""))
                    .getClaim("role").asString();

                if (user != null) {
                    // empty authorities
                    return new UsernamePasswordAuthenticationToken(user, null,
                        List.of(new SimpleGrantedAuthority(role)));
                }
            }catch (SignatureVerificationException ex){
                logger.error("Invalid JWT Signature");
            }catch (TokenExpiredException ex){
                logger.error("Expired JWT jwtToken");
                request.setAttribute("expired", ex.getMessage());
            }catch (AlgorithmMismatchException ex){
                logger.error("Unsupported JWT exception");
            }catch (InvalidClaimException ex){
                logger.error("Jwt claims string is empty");
            }
            return null;
        }
        return null;
    }
}