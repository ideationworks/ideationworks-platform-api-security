package ideation.platform.api.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.cors().and().csrf().disable().authorizeRequests().antMatchers("/monitoring/is_alive",
                                                                           "/users/login",
                                                                           "/users/reset/**",
                                                                           "/users/register",
                                                                           "/users/confirm/**").permitAll().anyRequest().authenticated().and()
            // We filter the api/login requests
            // And filter other requests to check the presence of JWT in header
            .addFilterBefore(new JWTAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

    }

}
