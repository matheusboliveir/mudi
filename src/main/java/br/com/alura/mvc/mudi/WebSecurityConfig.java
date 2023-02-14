package br.com.alura.mvc.mudi;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class WebSecurityConfig {

    private DataSource dataSource;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(
                auth -> auth.antMatchers("/home/**").permitAll().anyRequest().authenticated()
        ).formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/usuario/pedido", true)
                .permitAll()
        ).logout(logout -> logout.logoutUrl("/logout").logoutSuccessUrl("/home"));
        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsManager users(DataSource dataSource) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
        //UserDetails user = User.builder().username("admin").password(encoder.encode("admin")).roles("ADM").build();
        //users.createUser(user);
        return users;
    }
}
