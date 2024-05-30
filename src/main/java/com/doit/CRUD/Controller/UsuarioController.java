package com.doit.CRUD.Controller;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.CrossOrigin;

import com.doit.CRUD.Model.Usuario;
import com.doit.CRUD.service.UsuarioService;
@CrossOrigin(origins = "https://doitwebsite.netlify.app")
@RestController
@RequestMapping("users")
public class UsuarioController {

	@Autowired
	UsuarioService usuarioService;

	@GetMapping
	public List<Usuario> getUsers() {
		return usuarioService.getUsers();
	}

	@GetMapping(path = "/{id}")
	public Optional<Usuario> getTask(@PathVariable Integer id) {
		return usuarioService.getUser(id);
	}

	@PostMapping
	public Usuario saveUser(@RequestBody Usuario user) {
		return usuarioService.saveUser(user);
	}

	@PutMapping("/{id}/reg")
	public Usuario regUser(@PathVariable Integer id) {
		return usuarioService.regUser(id);
	}

	@PutMapping("/{id}/unReg")
	public Usuario unRegUser(@PathVariable Integer id) {
		return usuarioService.unRegUser(id);
	}
	@PostMapping("/register")
    public Usuario register(@RequestBody Usuario usuario) {
		System.out.println(usuario.getUSU_PASS());
        return usuarioService.registerUser(usuario);
    }

    @PostMapping("/login")
    public Usuario login(@RequestBody Usuario usuario) {
        Usuario existingUser = usuarioService.findByUsername(usuario.getUSU_NOM());
        if (existingUser != null && usuarioService.checkPassword(usuario.getUSU_PASS(), existingUser.getUSU_PASS())) {
            return usuarioService.findByUsername(usuario.getUSU_NOM());
        } else {
            return null;
        }
    }
}
