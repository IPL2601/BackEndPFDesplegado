package com.doit.CRUD.Request;

import com.doit.CRUD.Model.Task;

public class TaskRequest {
	private Task task;
	private Integer userId;

	// Getters y setters
	public Task getTask() {
		return task;
	}

	public void setTask(Task task) {
		this.task = task;
	}

	public Integer getUserId() {
		return userId;
	}

	public void setUserId(Integer userId) {
		this.userId = userId;
	}
}
