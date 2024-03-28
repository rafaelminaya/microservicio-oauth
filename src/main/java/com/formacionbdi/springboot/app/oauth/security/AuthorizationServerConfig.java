package com.formacionbdi.springboot.app.oauth.security;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

/*
 * Configuración del "Authorization Server", encagardo de todo el proceso de autenticación por el lado de OAuth2,
 * como login, crear el token, validar token, etc.
 * 
 * Utlizando el "Authentication Manager"(con todos los usuarios y roles asignados en el "UserDetailsService" y su implementación.
 *  
 * @EnableAuthorizationServer : 
 * Permite habilitar esta "clase de configuración" para el uso del "Authorization Server"
 * 
 * @RefreshScope
 * Anotación que permite actualizar los componentes del contenedor de spring en tiempo real, sin reiniciar la aplicación.
 * Es decir, aquellas clases anotadas con @Component y sus derivados (@Service, @RestController, etc).
 * Esto también aplica a los atributos inyectados con @Value y @Autowired.
 * Este proecedimiento se realizará mediante un endpoint de Spring Actuator
 * Requiere instalar esta dependencia en el "pom.xml"
 */
@RefreshScope
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	
	@Autowired
	private Environment environment;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	// El "Authentication Manager" lo registraremos en el "Authorization Server"
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private InfoAdicionalToken infoAdicionalToken;

	// Métodos sobre escritos por al herencia de la clase "AuthorizationServerConfigurerAdapter"
	
	// Configuración de los permisos que tendrán nuestros endpoints del "servidor de autorización" para generar y validar el token
	// Es decir el permiso de acceso para el endpoint "/oauth/token"
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		
		/*
		 * Crearemos 2 rutas/enpoints, que por defecto estarán protegidas por la autenticación vía "http basic", 
		 * al usar las credenciales del cliente/aplicación que son el "cliente id" y el "secret", enviados en las cabeceras de las peticiones.
		 * 
		 * tokenKeyAccess() : 
		 * Permite dar permisos, generando el token una vez autenticado.
		 *  
		 * "permitAll()" : 
		 * Método, propio de Spring Security, que da permiso a cualquier usuario para poder atutenticarse.
		 * Por defecto en el enpoint "/oauth/token"
		 * 
		 * checkTokenAccess() :
		 * Valida el token que se recibe del cliente. 
		 * Es un permiso al endpoint que se encarga de validar el token.
		 * Por defecto en el enpoint "/oauth/check_token"
		 * 
		 * isAuthenticated() : 
		 * Método propio de Spring security, para indicar que solo pueden acceder a esta ruta los clientes autenticados.
		 * 
		 */	
		security.tokenKeyAccess("permiteAll()")
		.checkTokenAccess("isAuthenticated()");
	}

	/*
	 * Registramos nuestros clientes (aplicaciones frontend) que accederán a nuestros microservicios como android, angular, react, etc.
	 * 
	 * En el estandar oauth ademas de autenticar con los usuarios del backend tambien con las credenciales de nuestro cliente, teniendo doble autenticación
	 */
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory()
		.withClient(this.environment.getProperty("config.security.oauth.client.id")) // id del cliente frontend
		.secret(this.bCryptPasswordEncoder.encode(this.environment.getProperty("config.security.oauth.client.secret"))) // password(encriptada) del cliente frontend
		.scopes("read", "write") // Asignamos el alcance/permiso para esta aplicación cliente
		/*
		 * authorizedGrantTypes()
		 * Indicamos el "tipo de concesión" que va a tener nuesta autenticación
		 * Es decir, cómo vamos a obtener el JWT. 
		 * 
		 * "password"
		 * Indica que además de enviar las credenciales del cliente frontend, 
		 * enviaremos las credenciales del usuario(usuario y password) que iniciará sesión en el backend.
		 * 
		 * "refresh_token"
		 * Concesión que genera un token de acceso renovado.
		 * Permite generar un nuevo token antes de que caduque el token actual.
		 */
		.authorizedGrantTypes("password", "refresh_token")
		.accessTokenValiditySeconds(3600) // Tiempo de caducidad del token de 3600 segundos(1 hora)
		.refreshTokenValiditySeconds(3600); // Tiempo de caducidad del token de 3600 segundos(1 hora)

		
		
	}

	// Configuracion dirigida al endpoint de OAuth2 "/oauth/token" que se encarga de generar el token 
	// Configuramos el "Authentication Manager", token storage(jwt), access token converter, que se encargar de guardar los "claims" (la información al token) 
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		
		// Clase que permite personalizar el token con información adicional
		TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
		tokenEnhancerChain.setTokenEnhancers(Arrays.asList(this.infoAdicionalToken, this.jwtAccessTokenConverter()));
		
		// Acá registramos al "Authentication Manager"
		endpoints.authenticationManager(this.authenticationManager)
		.tokenStore(this.tokenStore()) // Genera el token con los datos que se le hayan configurado en el argumento
		.accessTokenConverter(this.jwtAccessTokenConverter()) // Indicamos que el token será del estándar JWT
		.tokenEnhancer(tokenEnhancerChain); // agregamos la nueva cadena a la configuración del token
	}
	
	// Método que crea un nuevo token de estándar JWT, utilizando lo almacenado en el "JwtAccessTokenConverter"
	public JwtTokenStore tokenStore() {
		return new JwtTokenStore(this.jwtAccessTokenConverter());
	}

	// Método que devuelve un token del estándar JWT personalizando algunos datos, en este caso el "secret" de su firma
	@Bean
	JwtAccessTokenConverter jwtAccessTokenConverter() {
		
		JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
	
		// Asignamos el "codigo secreto" para la firma del JWT.
		accessTokenConverter.setSigningKey(this.environment.getProperty("config.security.oauth.jwt.key"));
		return accessTokenConverter;
		
	}		
	
}
