package com.formacionbdi.springboot.app.oauth.services;

import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.formacionbdi.springboot.app.commons.usuarios.models.entity.Usuario;
import com.formacionbdi.springboot.app.oauth.clients.UsuarioFeignClient;

import feign.FeignException;

/*
 * UserDetailsService
 * Interfaz propia de spring security
 */
@Service
public class UsuarioService implements UserDetailsService, IUsuarioService {

	private Logger logger = LoggerFactory.getLogger(UsuarioService.class);

	@Autowired
	private UsuarioFeignClient feignClient;

	// Método encargado de obtener al usuario por su "username", usando Feign
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// Validación de que exista el usuario buscado
		try {

			// Obteniendo el usuario de la base de datos con Feign desde el "servicio-usuarios"
			Usuario usuario = this.feignClient.findByUsername(username);

			// Convertimos el role del usuario obtenido al tipo "SimpleGrantedAuthority", el
			// cual es una instancia de "GrantedAuthority"
			List<GrantedAuthority> authorities = usuario.getRoles().stream()
					.map(role -> new SimpleGrantedAuthority(role.getNombre()))
					.peek(authorithy -> logger.info("Role: " + authorithy.getAuthority())).collect(Collectors.toList());

			logger.info("Usuario autenticado: " + username);
			// Retornamos una instacia de la clase "User", que es propia de "spring security", el cual es una instancia de la interfaz "UserDetails"
			// Esta instancia es el tipo de dato de la firma del método.
			return new User(usuario.getUsername(), usuario.getPassword(), usuario.getEnabled(), true, true, true,
					authorities);
		} catch (FeignException e) {
			logger.error("Error en el login. No existe el usuario '" + username + "' en el sistema");
			throw new UsernameNotFoundException("Error en el login. No existe el usuario '" + username + "' en el sistema");
		}
	}

	@Override
	public Usuario findByUsername(String username) {
		return this.feignClient.findByUsername(username);
	}

	@Override
	public Usuario update(Usuario usuario, Long id) {
		return this.feignClient.update(usuario, id);
	}

}
