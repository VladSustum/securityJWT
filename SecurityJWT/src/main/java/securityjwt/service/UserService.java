package securityjwt.service;

import org.springframework.web.multipart.MultipartFile;
import securityjwt.domain.User;
import securityjwt.exception.domain.*;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.List;

public interface UserService {

    User register(String firstName, String lastName, String username, String email) throws UserNotFoundException, EmailExistException, UserNameExistException, MessagingException;

    List<User> getUsers();

    User findByUserName(String username);

    User findByUserByEmail(String email);

    User addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNotLocked,
                    boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UserNameExistException, IOException, NotAnImageFileException;

    User updateUser(String currentUserName,String newFirstName, String newLastName, String newUserName, String newEmail, String role, boolean isNotLocked,
                    boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UserNameExistException, IOException, NotAnImageFileException;

    void deleteUser(String username);

    void resetPassword(String email) throws EmailNotFoundException, MessagingException;

    User updateProfileImage(String username,MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UserNameExistException, IOException, NotAnImageFileException;
}
