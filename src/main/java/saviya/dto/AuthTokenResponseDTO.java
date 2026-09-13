package saviya.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Access and refresh tokens issued after sign-in, sign-up, or token refresh")
public class AuthTokenResponseDTO {

  @Schema(description = "Short-lived JWT. Send as Authorization: Bearer <accessToken> on subsequent requests.")
  private String accessToken;

  @Schema(description = "Long-lived opaque token. Exchange it at POST /manage-users/refresh for a new token pair. The presented token is consumed.")
  private String refreshToken;

  @Schema(description = "HTTP Authorization scheme for the access token", example = "Bearer")
  private String tokenType;

  @Schema(description = "Access token lifetime in seconds from the time it was issued", example = "3600")
  private long expiresIn;

}
