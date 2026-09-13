package saviya;

import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import saviya.model.AppUser;
import saviya.model.AppUserRole;
import saviya.repository.UserRepository;
import saviya.service.UserManagementService;

@Component
@Profile("dev")
@RequiredArgsConstructor
public class DemoUserLoader implements CommandLineRunner {

  private final UserManagementService userManagementService;
  private final UserRepository userRepository;

  @Override
  public void run(String... args) {
    if (!userRepository.existsByUsername("admin")) {
      AppUser admin = new AppUser();
      admin.setUsername("admin");
      admin.setPassword("admin@abc");
      admin.setEmail("adabc@email.com");
      admin.setAppUserRoles(new ArrayList<>(List.of(AppUserRole.ROLE_ADMIN)));
      userManagementService.register(admin);
    }

    if (!userRepository.existsByUsername("client")) {
      AppUser client = new AppUser();
      client.setUsername("john");
      client.setPassword("john@123");
      client.setEmail("john@email.com");
      client.setAppUserRoles(new ArrayList<>(List.of(AppUserRole.ROLE_CLIENT)));
      userManagementService.register(client);
    }
  }
}
