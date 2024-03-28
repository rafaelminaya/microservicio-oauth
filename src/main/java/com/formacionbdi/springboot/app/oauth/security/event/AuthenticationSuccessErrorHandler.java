package com.formacionbdi.springboot.app.oauth.security.event;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import com.formacionbdi.springboot.app.commons.usuarios.models.entity.Usuario;
import com.formacionbdi.springboot.app.oauth.services.IUsuarioService;

import feign.FeignException;
/*
 * AuthenticationEventPublisher
 * Interfaz que al implementarla permite manipular los eventos al autenticarse con éxito o error
 */
@Component
public class AuthenticationSuccessErrorHandler implements AuthenticationEventPublisher {
	
	private Logger logger = LoggerFactory.getLogger(AuthenticationSuccessErrorHandler.class);
	
	@Autowired
	private IUsuarioService usuarioService;

	// Método para manipular el evento al autenticarse con éxito
	// "authentication" contiene la información del usuario ya autenticado
	@Override
	public void publishAuthenticationSuccess(Authentication authentication) {
		
		// 1° Opción - Validación para que el método no se ejecute 2 veces. 
		// Ya que se está ejecutando para el usuario frontend y el backend.		
		if(authentication.getDetails() instanceof WebAuthenticationDetails) {
			return;
		}
		
		// 2° Opción - Validación para que no entre en el código para verificaciones del usuario frontend
		/*
		if(authentication.getName().equalsIgnoreCase("frontendapp")) {
			return;
		}
		*/
		// Obtenemos la información del usuario autenticada y lo casteamos al tipo "UserDetails"
		UserDetails user = (UserDetails) authentication.getPrincipal();
		String mensaje = "Success login: " + user.getUsername();
		logger.info(mensaje);
		System.out.println(mensaje);
		
		// Reiniciamos a cero "0" el contador de intentos fallidos y persistimos en la base de datos
		Usuario usuario = this.usuarioService.findByUsername(authentication.getName());
		
		if(usuario.getIntentos() != null && usuario.getIntentos() > 0) {
			usuario.setIntentos(0);
			this.usuarioService.update(usuario, usuario.getId());
		}

	}

	// Método para manipular el evento al autenticarse con error
	// "authentication" contiene la información del usuario que intenta autenticar
	@Override
	public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
		String mensaje = "Error en el login: "+ exception.getMessage();
		logger.info(mensaje);
		System.out.println(mensaje);
		
		// Implementación de los 3 intentos de fracaso antes de bloquera la cuenta			
		// Controlamos la excepción en caso no encuentre al usuario
		try {
			Usuario usuario = this.usuarioService.findByUsername(authentication.getName());
			// Asignación de cero "0" intentos en caso este valor sea nulo(es decir que nunca haya iniciado sesión erroneamente) 
			if(usuario.getIntentos() == null) {
				usuario.setIntentos(0);
			}
			
			logger.info("Cantidad de intentos actual: " + usuario.getIntentos());
			
			// Ingrementamos cada intento			
			usuario.setIntentos(usuario.getIntentos() + 1);
			logger.info("Cantidad de intentos después: " + usuario.getIntentos());
			
			// En caso sean al menos 3 intentos acumulados deshabilitamos al usuario
			if(usuario.getIntentos() >= 3) {
				logger.error(String.format("El usuario %s deshabilitado por máximos intentos", usuario.getUsername()));
				usuario.setEnabled(false);
			}
			
			// Persistemos estos cambios en la base de datos
			this.usuarioService.update(usuario, usuario.getId());
			
		} catch (FeignException e) {
			logger.error(String.format("El usuario %s no existe en el sistema.", authentication.getName()));
		}
		
	}

}
