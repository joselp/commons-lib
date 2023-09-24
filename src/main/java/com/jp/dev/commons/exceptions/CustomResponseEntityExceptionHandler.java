package com.jp.dev.commons.exceptions;

import com.auth0.jwt.exceptions.TokenExpiredException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CustomResponseEntityExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(Exception.class)
    public final ResponseEntity<Object> handleAllException(Exception ex, WebRequest request) throws Exception {

        ExceptionResponse exceptionResponse = new ExceptionResponse(ex.getMessage(), request.getDescription(false));
        return new ResponseEntity<>(exceptionResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(NotFoundException.class)
    public final ResponseEntity<Object> handleUserNotFoundException(
        NotFoundException ex, WebRequest request) throws Exception {

        ExceptionResponse exceptionResponse = new ExceptionResponse(ex.getMessage(), request.getDescription(false));
        return new ResponseEntity<>(exceptionResponse, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(BadRequestException.class)
    public final ResponseEntity<Object> handleBadRequestException(
        BadRequestException ex, WebRequest request) throws Exception {
        ExceptionResponse exceptionResponse = new ExceptionResponse(ex.getMessage(), request.getDescription(false));
        return new ResponseEntity<>(exceptionResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ForbiddenException.class)
    public final ResponseEntity<Object> handleForbiddenException(
        ForbiddenException ex, WebRequest request) throws Exception {

        ExceptionResponse exceptionResponse = new ExceptionResponse(ex.getMessage(), request.getDescription(false));
        return new ResponseEntity<>(exceptionResponse, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(ConflictException.class)
    public final ResponseEntity<Object> handleConflictException(
        ConflictException ex, WebRequest request) throws Exception {

        ExceptionResponse exceptionResponse = new ExceptionResponse(ex.getMessage(), request.getDescription(false));
        return new ResponseEntity<>(exceptionResponse, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(TokenExpiredException.class)
    public final ResponseEntity<Object> handleTokenExpiredException(
        ConflictException ex, WebRequest request) throws Exception {
        ExceptionResponse exceptionResponse = new ExceptionResponse(ex.getMessage(), request.getDescription(false));
        return new ResponseEntity<>(exceptionResponse, HttpStatus.CONFLICT);
    }
}
