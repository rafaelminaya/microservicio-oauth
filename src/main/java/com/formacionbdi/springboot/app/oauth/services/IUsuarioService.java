package com.formacionbdi.springboot.app.oauth.services;

import com.formacionbdi.springboot.app.commons.usuarios.models.entity.Usuario;

public interface IUsuarioService {
	
	Usuario findByUsername(String username);
		
	Usuario update(Usuario usuario, Long id);

}
