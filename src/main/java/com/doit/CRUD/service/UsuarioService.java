package com.doit.CRUD.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.doit.CRUD.Model.Usuario;
import com.doit.CRUD.Repository.UsuarioRepository;

@Service
public class UsuarioService {
	@Autowired
	UsuarioRepository usuarioRepository;

	private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
	
	public ArrayList<Usuario> getUsers() {
		return (ArrayList<Usuario>) usuarioRepository.findAll();
	}

	public Optional<Usuario> getUser(Integer id) {
		return usuarioRepository.findById(id);
	}

	public Usuario saveUser(Usuario user) {
		return usuarioRepository.save(user);
	}

	public Usuario regUser(Integer id) {
		List<Usuario> usuarios = usuarioRepository.findAll();
		Usuario userModificado = usuarioRepository.findById(id).orElse(null);
		userModificado.setUSU_REG(true);
		return userModificado;
	}

	public Usuario unRegUser(Integer id) {
		Usuario userModificado = usuarioRepository.findById(id).orElse(null);
		userModificado.setUSU_REG(false);
		return userModificado;
	}
	
	public Usuario registerUser(Usuario usuario) {
        usuario.setUSU_PASS(passwordEncoder.encode(usuario.getUSU_PASS()));
        return usuarioRepository.save(usuario);
    }
	public boolean checkPassword(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }
	 public Usuario findByUsername(String username) {
	        return getByUSU_NOM(username);
	    }
	 private Usuario getByUSU_NOM(String nombre) {
		 Optional<Usuario> usuarioOpt = usuarioRepository.findAll().stream()
		            .filter(usuario -> usuario.getUSU_NOM().equals(nombre))
		            .findFirst();        
		        return usuarioOpt.orElse(null);
	 }
}
