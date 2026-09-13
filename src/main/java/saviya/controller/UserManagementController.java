package saviya.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;
import saviya.dto.AuthTokenResponseDTO;
import saviya.dto.RefreshRequestDTO;
import saviya.dto.UserDataDTO;
import saviya.dto.UserResponseDTO;
import saviya.model.AppUser;
import saviya.service.UserManagementService;

import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@RequestMapping("/manage-users")
//@Tag(name = "users")
@Tag(name = "manage-users")
@RequiredArgsConstructor
public class UserManagementController {

  private final UserManagementService userManagementService;
  private final ModelMapper modelMapper;

  @PostMapping("/signin")
  @Operation(
      summary = "Signs in a user and returns an access/refresh token pair",
      description = "Authenticates with username and password. No access token is required. "
          + "The response contains a short-lived JWT and a long-lived refresh token.")
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Authentication succeeded; token pair issued"),
      @ApiResponse(responseCode = "400", description = "Missing or invalid request parameters"),
      @ApiResponse(responseCode = "422", description = "Invalid username or password")})
  public AuthTokenResponseDTO login(
      @Parameter(description = "Account username") @RequestParam String username,
      @Parameter(description = "Account password") @RequestParam String password) {
    return userManagementService.signin(username, password);
  }

  @PostMapping("/signup")
  @Operation(
      summary = "Registers a new user",
      description = "Creates the account only. No tokens are issued. "
          + "Call POST /manage-users/signin afterwards to obtain an access/refresh token pair.")
  @ApiResponses(value = {
      @ApiResponse(responseCode = "201", description = "User created"),
      @ApiResponse(responseCode = "400", description = "Invalid username, email, or password"),
      @ApiResponse(responseCode = "422", description = "Username is already in use")})
  @ResponseStatus(HttpStatus.CREATED)
  public UserResponseDTO register(
      @Parameter(description = "New user details") @RequestBody @Valid UserDataDTO user) {
    AppUser created = userManagementService.register(modelMapper.map(user, AppUser.class));
    return modelMapper.map(created, UserResponseDTO.class);
  }

  @DeleteMapping(value = "/{username}")
  @PreAuthorize("hasRole('ROLE_ADMIN')")
  @Operation(
      summary = "Deletes a user by username",
      description = "Requires ROLE_ADMIN. Also revokes that user's refresh tokens.")
  @SecurityRequirement(name = "bearerAuth")
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "User deleted; response body is the username"),
      @ApiResponse(responseCode = "401", description = "Expired or invalid access token"),
      @ApiResponse(responseCode = "403", description = "Caller is not an admin"),
      @ApiResponse(responseCode = "404", description = "The user doesn't exist")})
  public String delete(
      @Parameter(description = "Username of the user to delete") @PathVariable String username) {
    userManagementService.delete(username);
    return username;
  }

  @GetMapping(value = "/{username}")
  @PreAuthorize("hasRole('ROLE_ADMIN')")
  @Operation(
      summary = "Returns a user by username",
      description = "Requires ROLE_ADMIN. Password is not included in the response.")
  @SecurityRequirement(name = "bearerAuth")
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "User found"),
      @ApiResponse(responseCode = "401", description = "Expired or invalid access token"),
      @ApiResponse(responseCode = "403", description = "Caller is not an admin"),
      @ApiResponse(responseCode = "404", description = "The user doesn't exist")})
  public UserResponseDTO search(
      @Parameter(description = "Username of the user to look up") @PathVariable String username) {
    return modelMapper.map(userManagementService.search(username), UserResponseDTO.class);
  }

  @GetMapping(value = "/me")
  @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_CLIENT')")
  @Operation(
      summary = "Returns the authenticated user",
      description = "Requires a valid access token and ROLE_ADMIN or ROLE_CLIENT. "
          + "Password is not included in the response.")
  @SecurityRequirement(name = "bearerAuth")
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Authenticated user found"),
      @ApiResponse(responseCode = "401", description = "Expired or invalid access token"),
      @ApiResponse(responseCode = "403", description = "Caller is not an admin or client"),
      @ApiResponse(responseCode = "404", description = "The user doesn't exist")})
  public UserResponseDTO getCurrentUser(HttpServletRequest req) {
    return modelMapper.map(userManagementService.getCurrentUser(req), UserResponseDTO.class);
  }

  @PostMapping("/refresh")
  @Operation(
      summary = "Exchanges a refresh token for a new access/refresh token pair",
      description = "Does not require an access token, so it works after the access token has expired. "
          + "The presented refresh token is consumed and replaced by the one in the response. "
          + "Reusing a consumed token returns 401 and revokes all refresh tokens for that user.")
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "New token pair issued"),
      @ApiResponse(responseCode = "400", description = "Missing or blank refresh token"),
      @ApiResponse(responseCode = "401", description = "Expired, invalid, or already used refresh token"),
      @ApiResponse(responseCode = "404", description = "The user doesn't exist")})
  public AuthTokenResponseDTO refresh(@RequestBody @Valid RefreshRequestDTO request) {
    return userManagementService.refresh(request.getRefreshToken());
  }

  @PostMapping("/logout")
  @Operation(
      summary = "Revokes a refresh token",
      description = "No access token required. Unknown or already-revoked tokens still return 204. "
          + "The access token stays valid until it expires.")
  @ApiResponses(value = {
      @ApiResponse(responseCode = "204", description = "Refresh token revoked"),
      @ApiResponse(responseCode = "400", description = "Missing or blank refresh token")})
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void logout(@RequestBody @Valid RefreshRequestDTO request) {
    userManagementService.logout(request.getRefreshToken());
  }

}
