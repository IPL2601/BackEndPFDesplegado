package com.doit.CRUD.Model;

import java.util.Date;

import jakarta.annotation.Nonnull;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class Task {
	
	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
    private Integer TASK_ID;

    @Nonnull
    private String TASK_NOM;

    @Nonnull
    private String TASK_DESC;
   
    @Nonnull
    private String TASK_PRI;
    
    @Nonnull
    private Boolean TASK_DONE;
    
    @Nonnull
    private Integer TASK_USU;
    
    @Nonnull
    private Date TASK_DATE;
    

	public Task() {
    }

    public Task(Integer TASK_ID, String TASK_NOM, String TASK_DESC, String TASK_PRI, Boolean TASK_DONE) {
        this.TASK_ID = TASK_ID;
        this.TASK_NOM = TASK_NOM;
        this.TASK_DESC = TASK_DESC;
        this.TASK_PRI = TASK_PRI;
        this.TASK_DONE = TASK_DONE;
    }

    public Task(String TASK_NOM, String TASK_DESC, String TASK_PRI, Boolean TASK_DONE) {
    	this.TASK_NOM = TASK_NOM;
    	this.TASK_DESC = TASK_DESC;
    	this.TASK_PRI = TASK_PRI;
    	this.TASK_DONE = TASK_DONE;
    }
    public Integer getTASK_ID() {
        return TASK_ID;
    }

    public void setTASK_ID(Integer TASK_ID) {
        this.TASK_ID = TASK_ID;
    }

    public String getTASK_NOM() {
        return TASK_NOM;
    }

    public void setTASK_NOM(String TASK_NOM) {
        this.TASK_NOM = TASK_NOM;
    }

    public String getTASK_DESC() {
        return TASK_DESC;
    }

    public void setTASK_DESC(String TASK_DESC) {
        this.TASK_DESC = TASK_DESC;
    }

    public String getTASK_PRI() {
        return TASK_PRI;
    }

    public void setTASK_PRI(String TASK_PRI) {
        this.TASK_PRI = TASK_PRI;
    }

    public Boolean getTASK_DONE() {
        return TASK_DONE;
    }

    public void setTASK_DONE(Boolean TASK_DONE) {
        this.TASK_DONE = TASK_DONE;
    }
    
    
    public Integer getTASK_USU() {
		return TASK_USU;
	}

	public void setTASK_USU(Integer TASK_USU) {
		this.TASK_USU = TASK_USU;
	}

	public Date getTASK_DATE() {
		return TASK_DATE;
	}

	public void setTASK_DATE(Date tASK_DATE) {
		TASK_DATE = tASK_DATE;
	}
}
