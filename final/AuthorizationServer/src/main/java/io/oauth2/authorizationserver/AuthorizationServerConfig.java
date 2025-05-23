package io.oauth2.authorizationserver;


import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    @Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();


        authorizationServerConfigurer.authorizationEndpoint(

                authorizationEndpoint->authorizationEndpoint


                        .authenticationProvider(customAuthenticationProvider)


                        .errorResponseHandler((request, response, exception) -> {
                            System.out.println(exception.toString());
                            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                        })


        );


        authorizationServerConfigurer.oidc(Customizer.withDefaults());

        ((HttpSecurity) http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, Customizer.withDefaults()))
                .authorizeHttpRequests((authorize) -> {
                    authorize.requestMatchers("/login").permitAll();
            ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl) authorize.anyRequest()).authenticated();
        });

        http.exceptionHandling(ex->ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

        http.oauth2ResourceServer(resourceServerConfigurer->resourceServerConfigurer.jwt(Customizer.withDefaults()));

        http.formLogin(Customizer.withDefaults());

        SecurityFilterChain build =(SecurityFilterChain) http.build();
        return build;










//
//        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
//
//
//     RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
//
//        http
//                .securityMatcher(endpointsMatcher)
//                .authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers("/login").permitAll()
//                        .anyRequest().authenticated()
//                )
//                .formLogin(form-> form.loginPage("/login"))
//                .csrf(csrf -> csrf
//                        .ignoringRequestMatchers(endpointsMatcher)
//                )
//                .exceptionHandling(exceptions -> exceptions
//                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
//                )
//                .with(authorizationServerConfigurer, Customizer.withDefaults())
//
//
//
//        ;
//
//
//        return http.build();
    }
}

