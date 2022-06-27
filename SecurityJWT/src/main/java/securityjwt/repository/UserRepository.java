package securityjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import securityjwt.domain.User;

public interface  UserRepository extends JpaRepository<User,Long> {

    User findUserByUsername(String username);

    User findUserByEmail(String email);

}
