package saviya.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import saviya.dto.AuthTokenResponseDTO;
import saviya.exception.CustomException;
import saviya.exception.GlobalExceptionHandlerController;
import saviya.model.AppUser;
import saviya.model.AppUserRole;
import saviya.security.JwtTokenProvider;
import saviya.security.WebSecurityConfig;
import saviya.service.UserManagementService;

@WebMvcTest(controllers = UserManagementController.class)
@Import({WebSecurityConfig.class, GlobalExceptionHandlerController.class})
@DisplayName("User management HTTP API")
class UserManagementControllerWebTest {

  private static final String API = "/manage-users";

  @Autowired
  private MockMvc mockMvc;

  @MockitoBean
  private UserManagementService userManagementService;

  @MockitoBean
  private JwtTokenProvider jwtTokenProvider;

  @Nested
  @DisplayName("Sign in")
  class SignIn {

    @Test
    @DisplayName("valid credentials return a Bearer token pair")
    void validCredentialsReturnTokenPair() throws Exception {
      when(userManagementService.signin("admin", "admin123456"))
          .thenReturn(new AuthTokenResponseDTO("access-jwt", "refresh-opaque", "Bearer", 300));

      mockMvc.perform(post(API + "/signin")
              .param("username", "admin")
              .param("password", "admin123456"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.accessToken").value("access-jwt"))
          .andExpect(jsonPath("$.refreshToken").value("refresh-opaque"))
          .andExpect(jsonPath("$.tokenType").value("Bearer"))
          .andExpect(jsonPath("$.expiresIn").value(300));
    }

    @Test
    @DisplayName("invalid credentials are unprocessable")
    void invalidCredentialsAreUnprocessable() throws Exception {
      when(userManagementService.signin("admin", "wrong"))
          .thenThrow(new CustomException("Invalid user credentials", HttpStatus.UNPROCESSABLE_ENTITY));

      mockMvc.perform(post(API + "/signin")
              .param("username", "admin")
              .param("password", "wrong"))
          .andExpect(status().isUnprocessableEntity());
    }
  }

  @Nested
  @DisplayName("Registration")
  class Registration {

    @Test
    @DisplayName("new account is created without tokens")
    void newAccountIsCreatedWithoutTokens() throws Exception {
      when(userManagementService.register(any(AppUser.class))).thenAnswer(invocation -> {
        AppUser saved = invocation.getArgument(0);
        saved.setId(42);
        return saved;
      });

      mockMvc.perform(post(API + "/signup")
              .contentType(MediaType.APPLICATION_JSON)
              .content(registrationJson("member01", "member01@saviya.test", "securePass1")))
          .andExpect(status().isCreated())
          .andExpect(jsonPath("$.id").value(42))
          .andExpect(jsonPath("$.username").value("member01"))
          .andExpect(jsonPath("$.email").value("member01@saviya.test"))
          .andExpect(jsonPath("$.password").doesNotExist())
          .andExpect(jsonPath("$.accessToken").doesNotExist())
          .andExpect(jsonPath("$.refreshToken").doesNotExist());
    }

    @Test
    @DisplayName("duplicate username is unprocessable")
    void duplicateUsernameIsUnprocessable() throws Exception {
      when(userManagementService.register(any(AppUser.class)))
          .thenThrow(new CustomException("Username is already in use", HttpStatus.UNPROCESSABLE_ENTITY));

      mockMvc.perform(post(API + "/signup")
              .contentType(MediaType.APPLICATION_JSON)
              .content(registrationJson("admin", "other@saviya.test", "securePass1")))
          .andExpect(status().isUnprocessableEntity());
    }

    @Test
    @DisplayName("password shorter than eight characters is a bad request")
    void shortPasswordIsBadRequest() throws Exception {
      mockMvc.perform(post(API + "/signup")
              .contentType(MediaType.APPLICATION_JSON)
              .content(registrationJson("short01", "short01@saviya.test", "tiny")))
          .andExpect(status().isBadRequest());

      verify(userManagementService, never()).register(any());
    }
  }

  @Nested
  @DisplayName("Current user")
  class CurrentUser {

    @Test
    @DisplayName("authenticated client receives their profile")
    void authenticatedClientReceivesProfile() throws Exception {
      when(userManagementService.getCurrentUser(any())).thenReturn(sampleUser(7, "client", "client@email.com", AppUserRole.ROLE_CLIENT));

      mockMvc.perform(get(API + "/me").with(user("client").roles("CLIENT")))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.username").value("client"))
          .andExpect(jsonPath("$.email").value("client@email.com"))
          .andExpect(jsonPath("$.password").doesNotExist())
          .andExpect(jsonPath("$.appUserRoles[0]").value("ROLE_CLIENT"));
    }

    @Test
    @DisplayName("anonymous caller is forbidden")
    void anonymousCallerIsForbidden() throws Exception {
      mockMvc.perform(get(API + "/me"))
          .andExpect(status().isForbidden());

      verify(userManagementService, never()).getCurrentUser(any());
    }
  }

  @Nested
  @DisplayName("Token refresh and logout")
  class RefreshAndLogout {

    @Test
    @DisplayName("valid refresh token returns a rotated pair")
    void validRefreshReturnsRotatedPair() throws Exception {
      when(userManagementService.refresh("old-refresh"))
          .thenReturn(new AuthTokenResponseDTO("new-access", "new-refresh", "Bearer", 300));

      mockMvc.perform(post(API + "/refresh")
              .contentType(MediaType.APPLICATION_JSON)
              .content(refreshJson("old-refresh")))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.accessToken").value("new-access"))
          .andExpect(jsonPath("$.refreshToken").value("new-refresh"))
          .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    @DisplayName("unknown refresh token is unauthorized")
    void unknownRefreshTokenIsUnauthorized() throws Exception {
      when(userManagementService.refresh("unknown"))
          .thenThrow(new CustomException("Invalid refresh token", HttpStatus.UNAUTHORIZED));

      mockMvc.perform(post(API + "/refresh")
              .contentType(MediaType.APPLICATION_JSON)
              .content(refreshJson("unknown")))
          .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("blank refresh token is a bad request")
    void blankRefreshTokenIsBadRequest() throws Exception {
      mockMvc.perform(post(API + "/refresh")
              .contentType(MediaType.APPLICATION_JSON)
              .content(refreshJson("")))
          .andExpect(status().isBadRequest());

      verify(userManagementService, never()).refresh(any());
    }

    @Test
    @DisplayName("logout of any token returns no content")
    void logoutReturnsNoContent() throws Exception {
      mockMvc.perform(post(API + "/logout")
              .contentType(MediaType.APPLICATION_JSON)
              .content(refreshJson("any-token")))
          .andExpect(status().isNoContent());

      verify(userManagementService).logout("any-token");
    }
  }

  @Nested
  @DisplayName("Admin lookup and delete")
  class AdminOperations {

    @Test
    @DisplayName("admin can look up a user")
    void adminCanLookUpUser() throws Exception {
      when(userManagementService.search("client"))
          .thenReturn(sampleUser(2, "client", "client@email.com", AppUserRole.ROLE_CLIENT));

      mockMvc.perform(get(API + "/client").with(user("admin").roles("ADMIN")))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.username").value("client"))
          .andExpect(jsonPath("$.email").value("client@email.com"))
          .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    @DisplayName("client cannot look up another account")
    void clientCannotLookUpAnotherAccount() throws Exception {
      mockMvc.perform(get(API + "/admin").with(user("client").roles("CLIENT")))
          .andExpect(status().isForbidden());

      verify(userManagementService, never()).search(any());
    }

    @Test
    @DisplayName("missing username returns not found")
    void missingUsernameIsNotFound() throws Exception {
      when(userManagementService.search("ghost-user"))
          .thenThrow(new CustomException("The user doesn't exist", HttpStatus.NOT_FOUND));

      mockMvc.perform(get(API + "/ghost-user").with(user("admin").roles("ADMIN")))
          .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("admin can delete a user")
    void adminCanDeleteUser() throws Exception {
      mockMvc.perform(delete(API + "/member01").with(user("admin").roles("ADMIN")))
          .andExpect(status().isOk())
          .andExpect(content().string("member01"));

      verify(userManagementService).delete("member01");
    }

    @Test
    @DisplayName("client cannot delete another account")
    void clientCannotDeleteAnotherAccount() throws Exception {
      mockMvc.perform(delete(API + "/admin").with(user("client").roles("CLIENT")))
          .andExpect(status().isForbidden());

      verify(userManagementService, never()).delete(any());
    }

    @Test
    @DisplayName("deleting a missing user returns not found")
    void deletingMissingUserIsNotFound() throws Exception {
      doThrow(new CustomException("The user doesn't exist", HttpStatus.NOT_FOUND))
          .when(userManagementService).delete("ghost-user");

      mockMvc.perform(delete(API + "/ghost-user").with(user("admin").roles("ADMIN")))
          .andExpect(status().isNotFound());
    }
  }

  private static AppUser sampleUser(int id, String username, String email, AppUserRole role) {
    AppUser appUser = new AppUser();
    appUser.setId(id);
    appUser.setUsername(username);
    appUser.setEmail(email);
    appUser.setPassword("hashed-secret");
    appUser.setAppUserRoles(List.of(role));
    return appUser;
  }

  private static String refreshJson(String refreshToken) {
    return "{\"refreshToken\":\"" + refreshToken + "\"}";
  }

  private static String registrationJson(String username, String email, String password) {
    return """
        {"username":"%s","email":"%s","password":"%s","appUserRoles":["ROLE_CLIENT"]}
        """.formatted(username, email, password);
  }
}
