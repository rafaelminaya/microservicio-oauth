package com.formacionbdi.springboot.app.oauth.security;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

import com.formacionbdi.springboot.app.commons.usuarios.models.entity.Usuario;
import com.formacionbdi.springboot.app.oauth.services.IUsuarioService;

/*
 * TokenEnhancer
 * Interfaz que permite añadir información personalizada en el token(claims)
 */
@Component
public class InfoAdicionalToken implements TokenEnhancer {
	
	@Autowired
	private IUsuarioService usuarioService;
	
	// Método implementado por al interfaz "TokenEnhancer"
	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		// Obtenemos al usuario, donde su "username" será obtenido desde el argumento
		Usuario usuario = this.usuarioService.findByUsername(authentication.getName());
		// Mapa para guardar la información que se va a pesonalizar en el token
		Map<String, Object> info = new HashMap<String, Object>();
		info.put("nombre", usuario.getNombre());
		info.put("apellido", usuario.getApellido());
		info.put("correo", usuario.getEmail());
		// Por medio de la clase concreta "DefaultOAuth2AccessToken" que implementa a la interfaz "OAuth2AccessToken",
		// podremos usar al método "setAdditionalInformation()" que permite agregar información adicional al token.
		((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(info);
		// Devolvemos la información personalizada del token
		return accessToken;
	}
	

}
