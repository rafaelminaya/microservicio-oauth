package com.formacionbdi.springboot.app.oauth.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
	
	// Inyectamos esta interfaz, la cual fue implementada en nuestra clase "UsuarioService"
	// Implementando único método llamado "loadUserByUsername"
	@Autowired
	
	private UserDetailsService userDetailsService;
	// Interfaz implementada en nuestra clase "AuthenticationSuccessErrorHandler"
	// Registraremos la implementación de esta interfaz en el "authentication manager" para su funcionamiento
	@Autowired
	private AuthenticationEventPublisher authenticationEventPublisher;
	
	// Configuración y registro(como bean) de la clase service que implementa la interfaz "UserDetails" en el "Authentication Manager" de Spring Security
	// Este es un método sobre escrito de la clase padre "WebSecurityConfigurerAdapter".
	@Autowired
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		/*
		 * Acá registramos al "UserDetailsService" en el "Authentication Manager"
		 * Y con ".passwordEncoder()" encriptaremos la password de cada usuario al iniciar sesión(enviando por argumento el método que se usará para encriptar)
		 * y lo compará con la password guardada en la BD, la cual también debió haber sido almacenada en la BD usando "BCryptPasswordEncoder"
		 */
		auth.userDetailsService(this.userDetailsService).passwordEncoder(this.passwordEncoder())
		.and()
		.authenticationEventPublisher(this.authenticationEventPublisher); // Registramos nuestro "event publisher" en este "authentication manager"
		//auth.authenticationEventPublisher(this.authenticationEventPublisher);
		
		//super.configure(auth);
	}

    // Método que encripta un password usando la clase "BCryptPasswordEncoder"
    @Bean
    BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

    // Configuración y registro(como bean) del "authentication manager" 
    // Para luego utilizarlo/inyectarlo en la configuración del "servidor de autorización" de OAuth2
    @Bean
    @Override	
	protected AuthenticationManager authenticationManager() throws Exception {
		// TODO Auto-generated method stub
		return super.authenticationManager();
	}
          
}
