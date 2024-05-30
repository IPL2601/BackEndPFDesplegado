package com.doit.CRUD.Repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.doit.CRUD.Model.Usuario;
@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, Integer> {
	
}

