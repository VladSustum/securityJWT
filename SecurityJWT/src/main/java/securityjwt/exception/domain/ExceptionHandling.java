package securityjwt.exception.domain;

import com.auth0.jwt.exceptions.TokenExpiredException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import securityjwt.domain.HttpResponse;

import javax.persistence.NoResultException;
import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.util.Objects;

@RestControllerAdvice
public class ExceptionHandling {

    private Logger LOGGER = LoggerFactory.getLogger(getClass());

    public static final String ACCOUNT_LOCKED= "Your account has been locked.Contact administration";
    public static final String METHOD_IS_NOT_ALLOWED="This request method is not allowed on this endpoint.";
    public static final String INTERNAL_SERVER_ERROR_MSG="An error occurred while processing the request";
    public static final String INCORRECT_CREDENTIALS="Username/ password incorrect.Please try again";
    public static final String ACCOUNT_DISABLED ="Your account has been disabled.";
    public static final String ERROR_PROCESSING_FILE="Error occurred while processing file";
    public static final String NOT_ENOUGH_PERMISSION="You dont have enough permission";

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<HttpResponse> accountDisabledException(){
        return createHttpResponse(HttpStatus.BAD_REQUEST,ACCOUNT_DISABLED);
    }
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<HttpResponse> badCredentialsException(){
        return createHttpResponse(HttpStatus.BAD_REQUEST,INCORRECT_CREDENTIALS);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<HttpResponse> accessDeniedException(){
        return createHttpResponse(HttpStatus.FORBIDDEN,NOT_ENOUGH_PERMISSION);
    }
    @ExceptionHandler(LockedException.class)
    public ResponseEntity<HttpResponse> lockedException(){
        return createHttpResponse(HttpStatus.UNAUTHORIZED,ACCOUNT_LOCKED);

    }
    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<HttpResponse> tokenExpiredException(TokenExpiredException exception){
        return createHttpResponse(HttpStatus.UNAUTHORIZED,exception.getMessage());
    }

    @ExceptionHandler(EmailExistException.class)
    public ResponseEntity<HttpResponse> emailExistException(EmailExistException exception){
        return createHttpResponse(HttpStatus.BAD_REQUEST,exception.getMessage());
    }

    @ExceptionHandler(UserNameExistException.class)
    public ResponseEntity<HttpResponse> userNameExistException(UserNameExistException exception){
        return createHttpResponse(HttpStatus.BAD_REQUEST,exception.getMessage());
    }


    @ExceptionHandler(EmailNotFoundException.class)
    public ResponseEntity<HttpResponse> emailNotFoundException(EmailNotFoundException exception){
        return createHttpResponse(HttpStatus.BAD_REQUEST,exception.getMessage());
    }
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<HttpResponse> methodNotSupportedException(HttpRequestMethodNotSupportedException exception){

        return createHttpResponse(HttpStatus.BAD_REQUEST,exception.getMessage());
    }
    @ExceptionHandler(Exception.class)
    public ResponseEntity<HttpResponse>internalServerErrorException(Exception exception){
        LOGGER.error(exception.getMessage());
        return createHttpResponse(HttpStatus.INTERNAL_SERVER_ERROR,INTERNAL_SERVER_ERROR_MSG);
    }

    @ExceptionHandler(NotAnImageFileException.class)
    public ResponseEntity<HttpResponse> NotAnImageFileException(NotAnImageFileException exception){
        LOGGER.error(exception.getMessage());
        return createHttpResponse(HttpStatus.BAD_REQUEST,exception.getMessage());
    }

    @ExceptionHandler(NoResultException.class)
    public ResponseEntity<HttpResponse> notFoundException(NoResultException exception){
        LOGGER.error(exception.getMessage());
        return createHttpResponse(HttpStatus.NOT_FOUND,exception.getMessage());
    }
    @ExceptionHandler(IOException.class)
    public ResponseEntity<HttpResponse>iOException(IOException exception){
        LOGGER.error(exception.getMessage());

        return createHttpResponse(HttpStatus.INTERNAL_SERVER_ERROR,ERROR_PROCESSING_FILE);
    }

    private ResponseEntity<HttpResponse> createHttpResponse(HttpStatus httpStatus, String message){

        return new ResponseEntity<>(new HttpResponse(httpStatus.value(),httpStatus,httpStatus.getReasonPhrase(),
                message),httpStatus);
    }



}
