package com.configly.api;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import com.configly.web.ErrorCode;
import com.configly.web.ErrorResponse;
import com.configly.web.correlation.CorrelationId;

import java.time.Instant;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@RestControllerAdvice
@AllArgsConstructor
class ApiExceptionHandler {

    @ExceptionHandler(Exception.class)
    ResponseEntity<ErrorResponse> handleUnhandledException(Exception ex, HttpServletRequest request) {
        var errorResponse = createErrorResponse(ex, request);
        return ResponseEntity
                .status(INTERNAL_SERVER_ERROR)
                .body(errorResponse);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ErrorResponse> handle(MethodArgumentNotValidException ex, HttpServletRequest request) {
        var message = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining(", "));
        var errorResponse = new ErrorResponse(ErrorCode.VALIDATION_ERROR, message, extractCorrelationId(request).value(), Instant.now());
        return ResponseEntity
                .status(BAD_REQUEST)
                .body(errorResponse);
    }

    @ExceptionHandler(exception = {BindException.class, ConstraintViolationException.class, HttpMessageNotReadableException.class})
    ResponseEntity<ErrorResponse> handle(Exception ex, HttpServletRequest request) {
        var errorResponse = createErrorResponse(ex, request);
        return ResponseEntity
                .status(BAD_REQUEST)
                .body(errorResponse);
    }

    private ErrorResponse createErrorResponse(Exception e, HttpServletRequest request) {
        return ErrorResponse.from(ErrorCode.ERROR, e, extractCorrelationId(request));
    }

    private CorrelationId extractCorrelationId(HttpServletRequest request) {
        var value = request.getHeader(CorrelationId.headerName());
        return CorrelationId.of(value);
    }
}
