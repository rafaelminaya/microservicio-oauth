package com.formacionbdi.springboot.app.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/*
 * @EnableFeignClients
 * Habilita/permite el uso los "Feign client" que tengamos implementados en nuestro proyecto.
 * Además que permite inyectar nuestros "Feign client" en diversos componentes de spring(controllers, services, etc.)
 */
@EnableEurekaClient
@EnableFeignClients
@SpringBootApplication
public class SpringbootServicioOauthApplication implements CommandLineRunner {

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	public static void main(String[] args) {
		SpringApplication.run(SpringbootServicioOauthApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		
		String password = "12345";
		
		for (int i = 0; i < 4; i++) {
			String passwordBCrypt = this.bCryptPasswordEncoder.encode(password);
			System.out.println(passwordBCrypt);				
			
		}
	}

}
