package securityjwt.listener;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;
import securityjwt.service.LoginAttemptService;

import java.util.concurrent.ExecutionException;

@Component
public class AuthenticationFailureListener {

    private  LoginAttemptService loginAttemptService;


    @Autowired
    public AuthenticationFailureListener(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) throws ExecutionException {
        Object prinipal = event.getAuthentication().getPrincipal();
        if(prinipal instanceof  String){
            String username =(String) event.getAuthentication().getPrincipal();
            loginAttemptService.addUserToLoginAttemptCache(username);
        }
    }

}
