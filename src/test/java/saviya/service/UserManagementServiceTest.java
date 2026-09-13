package saviya.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import saviya.dto.AuthTokenResponseDTO;
import saviya.exception.CustomException;
import saviya.model.AppUser;
import saviya.model.AppUserRole;
import saviya.repository.UserRepository;
import saviya.security.JwtTokenProvider;

@ExtendWith(MockitoExtension.class)
class UserManagementServiceTest {

  @Mock
  private UserRepository userRepository;
  @Mock
  private PasswordEncoder passwordEncoder;
  @Mock
  private JwtTokenProvider jwtTokenProvider;
  @Mock
  private AuthenticationManager authenticationManager;
  @Mock
  private RefreshTokenService refreshTokenService;
  @Mock
  private HttpServletRequest request;

  @InjectMocks
  private UserManagementService userManagementService;

  private AppUser admin;

  @BeforeEach
  void setUp() {
    admin = new AppUser();
    admin.setId(1);
    admin.setUsername("admin");
    admin.setEmail("admin@email.com");
    admin.setPassword("secret");
    admin.setAppUserRoles(List.of(AppUserRole.ROLE_ADMIN));
  }

  @Test
  void signinIssuesAccessAndRefreshTokens() {
    when(userRepository.findByUsername("admin")).thenReturn(admin);
    when(jwtTokenProvider.createToken("admin", admin.getAppUserRoles())).thenReturn("access-jwt");
    when(refreshTokenService.issue("admin")).thenReturn("refresh-opaque");
    when(jwtTokenProvider.getValidityInSeconds()).thenReturn(300L);

    AuthTokenResponseDTO tokens = userManagementService.signin("admin", "admin123456");

    assertEquals("access-jwt", tokens.getAccessToken());
    assertEquals("refresh-opaque", tokens.getRefreshToken());
    assertEquals("Bearer", tokens.getTokenType());
    assertEquals(300L, tokens.getExpiresIn());
    verify(authenticationManager).authenticate(any());
  }

  @Test
  void signinRejectsBadCredentials() {
    when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("bad"));

    CustomException error = assertThrows(CustomException.class,
        () -> userManagementService.signin("admin", "wrong"));

    assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, error.getHttpStatus());
    verify(refreshTokenService, never()).issue(any());
  }

  @Test
  void registerEncodesPasswordAndSavesUser() {
    when(userRepository.existsByUsername("member01")).thenReturn(false);
    when(passwordEncoder.encode("plain-pass")).thenReturn("hashed-pass");
    when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

    AppUser created = new AppUser();
    created.setUsername("member01");
    created.setPassword("plain-pass");
    AppUser saved = userManagementService.register(created);

    assertEquals("hashed-pass", saved.getPassword());
    verify(userRepository).save(created);
  }

  @Test
  void registerRejectsDuplicateUsername() {
    when(userRepository.existsByUsername("admin")).thenReturn(true);

    CustomException error = assertThrows(CustomException.class, () -> userManagementService.register(admin));

    assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, error.getHttpStatus());
    verify(userRepository, never()).save(any());
  }

  @Test
  void deleteRemovesUserAndRefreshTokens() {
    when(userRepository.existsByUsername("member01")).thenReturn(true);

    userManagementService.delete("member01");

    verify(refreshTokenService).deleteAll("member01");
    verify(userRepository).deleteByUsername("member01");
  }

  @Test
  void deleteMissingUserIsNotFound() {
    when(userRepository.existsByUsername("ghost")).thenReturn(false);

    CustomException error = assertThrows(CustomException.class, () -> userManagementService.delete("ghost"));

    assertEquals(HttpStatus.NOT_FOUND, error.getHttpStatus());
    verify(userRepository, never()).deleteByUsername(any());
  }

  @Test
  void searchReturnsExistingUser() {
    when(userRepository.findByUsername("admin")).thenReturn(admin);

    assertEquals(admin, userManagementService.search("admin"));
  }

  @Test
  void searchMissingUserIsNotFound() {
    when(userRepository.findByUsername("ghost")).thenReturn(null);

    CustomException error = assertThrows(CustomException.class, () -> userManagementService.search("ghost"));

    assertEquals(HttpStatus.NOT_FOUND, error.getHttpStatus());
  }

  @Test
  void getCurrentUserReadsUsernameFromAccessToken() {
    when(jwtTokenProvider.resolveToken(request)).thenReturn("access-jwt");
    when(jwtTokenProvider.getUsername("access-jwt")).thenReturn("admin");
    when(userRepository.findByUsername("admin")).thenReturn(admin);

    assertEquals(admin, userManagementService.getCurrentUser(request));
  }

  @Test
  void getCurrentUserRejectsMissingToken() {
    when(jwtTokenProvider.resolveToken(request)).thenReturn(null);

    CustomException error = assertThrows(CustomException.class, () -> userManagementService.getCurrentUser(request));

    assertEquals(HttpStatus.UNAUTHORIZED, error.getHttpStatus());
  }

  @Test
  void refreshRotatesTokensForExistingUser() {
    when(refreshTokenService.rotate("old-refresh"))
        .thenReturn(new RefreshTokenService.Rotation("admin", "new-refresh"));
    when(userRepository.findByUsername("admin")).thenReturn(admin);
    when(jwtTokenProvider.createToken("admin", admin.getAppUserRoles())).thenReturn("new-access");
    when(jwtTokenProvider.getValidityInSeconds()).thenReturn(300L);

    AuthTokenResponseDTO tokens = userManagementService.refresh("old-refresh");

    assertEquals("new-access", tokens.getAccessToken());
    assertEquals("new-refresh", tokens.getRefreshToken());
  }

  @Test
  void logoutDelegatesToRefreshTokenService() {
    userManagementService.logout("refresh-token");

    verify(refreshTokenService).revoke("refresh-token");
  }
}
