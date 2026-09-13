package saviya.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import saviya.exception.CustomException;
import saviya.model.RefreshToken;
import saviya.repository.RefreshTokenRepository;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

  @Mock
  private RefreshTokenRepository refreshTokenRepository;

  @InjectMocks
  private RefreshTokenService refreshTokenService;

  @BeforeEach
  void setUp() {
    ReflectionTestUtils.setField(refreshTokenService, "refreshValidityInMilliseconds", 60_000L);
  }

  @Test
  void issuePersistsOnlyTheTokenHash() {
    when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

    String rawToken = refreshTokenService.issue("admin");

    ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
    verify(refreshTokenRepository).save(captor.capture());
    RefreshToken stored = captor.getValue();
    assertEquals(sha256(rawToken), stored.getTokenHash());
    assertEquals("admin", stored.getUsername());
    assertFalse(stored.isRevoked());
    assertTrue(stored.getExpiryDate().isAfter(Instant.now()));
  }

  @Test
  void rotateConsumesTheOldTokenAndReturnsAReplacement() {
    RefreshToken stored = token("admin", false, Instant.now().plusSeconds(60));
    when(refreshTokenRepository.findByTokenHash(sha256("old-refresh"))).thenReturn(Optional.of(stored));
    when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

    RefreshTokenService.Rotation rotation = refreshTokenService.rotate("old-refresh");

    assertEquals("admin", rotation.username());
    assertNotEquals("old-refresh", rotation.newRefreshToken());
    assertTrue(stored.isRevoked());
  }

  @Test
  void rotateUnknownTokenIsUnauthorized() {
    when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());

    CustomException error = assertThrows(CustomException.class, () -> refreshTokenService.rotate("missing"));

    assertEquals(HttpStatus.UNAUTHORIZED, error.getHttpStatus());
    verify(refreshTokenRepository, never()).revokeAllByUsername(any());
  }

  @Test
  void rotateRevokedTokenRevokesTheWholeFamily() {
    RefreshToken stored = token("admin", true, Instant.now().plusSeconds(60));
    when(refreshTokenRepository.findByTokenHash(sha256("stolen"))).thenReturn(Optional.of(stored));

    CustomException error = assertThrows(CustomException.class, () -> refreshTokenService.rotate("stolen"));

    assertEquals(HttpStatus.UNAUTHORIZED, error.getHttpStatus());
    verify(refreshTokenRepository).revokeAllByUsername("admin");
  }

  @Test
  void rotateExpiredTokenIsUnauthorized() {
    RefreshToken stored = token("admin", false, Instant.now().minusSeconds(5));
    when(refreshTokenRepository.findByTokenHash(sha256("expired"))).thenReturn(Optional.of(stored));

    CustomException error = assertThrows(CustomException.class, () -> refreshTokenService.rotate("expired"));

    assertEquals(HttpStatus.UNAUTHORIZED, error.getHttpStatus());
    verify(refreshTokenRepository, never()).revokeAllByUsername(any());
  }

  @Test
  void revokeMarksAKnownToken() {
    RefreshToken stored = token("admin", false, Instant.now().plusSeconds(60));
    when(refreshTokenRepository.findByTokenHash(sha256("refresh"))).thenReturn(Optional.of(stored));

    refreshTokenService.revoke("refresh");

    assertTrue(stored.isRevoked());
    verify(refreshTokenRepository).save(stored);
  }

  @Test
  void revokeIgnoresUnknownTokens() {
    when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());

    refreshTokenService.revoke("never-issued");

    verify(refreshTokenRepository, never()).save(any());
  }

  private static RefreshToken token(String username, boolean revoked, Instant expiry) {
    RefreshToken refreshToken = new RefreshToken();
    refreshToken.setUsername(username);
    refreshToken.setRevoked(revoked);
    refreshToken.setExpiryDate(expiry);
    return refreshToken;
  }

  private static String sha256(String raw) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
