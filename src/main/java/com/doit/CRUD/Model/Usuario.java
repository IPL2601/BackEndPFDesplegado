package com.doit.CRUD.Model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class Usuario {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer USU_COD;
    
    private String USU_NOM;

    private String USU_PASS;

    private Boolean USU_REG;

    public Usuario() {
        
    }

	public Integer getUSU_COD() {
		return USU_COD;
	}

	public void setUSU_COD(Integer uSU_COD) {
		USU_COD = uSU_COD;
	}

	public String getUSU_NOM() {
		return USU_NOM;
	}

	public void setUSU_NOM(String uSU_NOM) {
		USU_NOM = uSU_NOM;
	}

	public String getUSU_PASS() {
		return USU_PASS;
	}

	public void setUSU_PASS(String uSU_PASS) {
		USU_PASS = uSU_PASS;
	}

	public Boolean getUSU_REG() {
		return USU_REG;
	}

	public void setUSU_REG(Boolean uSU_REG) {
		USU_REG = uSU_REG;
	}

	public Usuario(Integer uSU_COD, String uSU_NOM, String uSU_PASS, Boolean uSU_REG) {
		USU_COD = uSU_COD;
		USU_NOM = uSU_NOM;
		USU_PASS = uSU_PASS;
		USU_REG = uSU_REG;
	}
	public Usuario(String uSU_NOM, String uSU_PASS, Boolean uSU_REG) {
		USU_NOM = uSU_NOM;
		USU_PASS = uSU_PASS;
		USU_REG = uSU_REG;
	}
	

}
