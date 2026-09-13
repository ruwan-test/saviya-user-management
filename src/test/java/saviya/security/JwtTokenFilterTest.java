package saviya.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import saviya.exception.CustomException;

@ExtendWith(MockitoExtension.class)
class JwtTokenFilterTest {

  @Mock
  private JwtTokenProvider jwtTokenProvider;
  @Mock
  private FilterChain filterChain;

  private JwtTokenFilter jwtTokenFilter;

  @BeforeEach
  void setUp() {
    jwtTokenFilter = new JwtTokenFilter(jwtTokenProvider);
    SecurityContextHolder.clearContext();
  }

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void publicRefreshPathSkipsJwtValidation() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("POST", "/manage-users/refresh");
    MockHttpServletResponse response = new MockHttpServletResponse();

    jwtTokenFilter.doFilter(request, response, filterChain);

    verify(jwtTokenProvider, never()).resolveToken(any());
    verify(filterChain).doFilter(request, response);
  }

  @Test
  void malformedTokenIsUnauthorized() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/manage-users/me");
    MockHttpServletResponse response = new MockHttpServletResponse();
    when(jwtTokenProvider.resolveToken(request)).thenReturn("not.a.jwt");
    when(jwtTokenProvider.validateToken("not.a.jwt"))
        .thenThrow(new CustomException("Expired or invalid JWT token", HttpStatus.UNAUTHORIZED));

    jwtTokenFilter.doFilter(request, response, filterChain);

    assertEquals(401, response.getStatus());
    verify(filterChain, never()).doFilter(any(), any());
  }

  @Test
  void validTokenPopulatesSecurityContext() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/manage-users/me");
    MockHttpServletResponse response = new MockHttpServletResponse();
    UsernamePasswordAuthenticationToken authentication =
        new UsernamePasswordAuthenticationToken("admin", "", java.util.List.of());
    when(jwtTokenProvider.resolveToken(request)).thenReturn("access-jwt");
    when(jwtTokenProvider.validateToken("access-jwt")).thenReturn(true);
    when(jwtTokenProvider.getAuthentication("access-jwt")).thenReturn(authentication);

    jwtTokenFilter.doFilter(request, response, filterChain);

    assertEquals(authentication, SecurityContextHolder.getContext().getAuthentication());
    verify(filterChain).doFilter(request, response);
  }
}
