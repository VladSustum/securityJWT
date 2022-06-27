package securityjwt.listener;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;
import securityjwt.domain.User;
import securityjwt.service.LoginAttemptService;

@Component
public class AuthenticationSuccessListener {

    private LoginAttemptService loginAttemptService;

    @Autowired
    public AuthenticationSuccessListener(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }
    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event){
        Object prinical = event.getAuthentication().getPrincipal();
        if(prinical instanceof User){
            User user = (User) event.getAuthentication().getPrincipal();
            loginAttemptService.evictUserFromLoginAttemptCache(user.getUsername());

        }
    }
}
