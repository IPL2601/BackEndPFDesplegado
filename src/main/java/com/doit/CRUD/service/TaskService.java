package com.doit.CRUD.service;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.doit.CRUD.Model.Task;
import com.doit.CRUD.Repository.TaskRepository;

import jakarta.persistence.EntityNotFoundException;

@Service
public class TaskService {
	@Autowired
	TaskRepository taskRepository;

	public ArrayList<Task> getTasks() {
		return (ArrayList<Task>) taskRepository.findAll();
	}

	public Optional<Task> getTask(Integer id) {
		return taskRepository.findById(id);
	}

	public Task saveTask(Task task, Integer userId) {
		task.setTASK_USU(userId);
		return taskRepository.save(task);
	}

	public Task updateTaskById(Task task, Integer id) {
		Task taskModificada = taskRepository.findById(id).orElse(null);
		taskModificada.setTASK_DESC(task.getTASK_DESC());
		taskModificada.setTASK_NOM(task.getTASK_NOM());
		taskModificada.setTASK_PRI(task.getTASK_PRI());
		taskModificada.setTASK_USU(task.getTASK_USU());
		taskModificada.setTASK_DATE(task.getTASK_DATE());
		return this.taskRepository.save(taskModificada);
	}

	public Task doTask(Integer id) {
		Task task = taskRepository.findById(id).orElse(null);

		if (task == null) {
			throw new EntityNotFoundException("Task not found with id: " + id);
		}
		
		if (task.getTASK_DONE()) {
			task.setTASK_DONE(false);			
		} else {
			task.setTASK_DONE(true);
		}

		taskRepository.save(task);

		return task;
	}

	public ArrayList<Task> getTaskByTaskUsu(Integer taskUsu) {
		return (ArrayList<Task>) taskRepository.findAll().stream().filter(t -> t.getTASK_USU().equals(taskUsu))
				.collect(Collectors.toList());
	}

	public ArrayList<Task> getTodayTasksByTaskUsu(Integer taskUsu) {
		List<Task> tasks = taskRepository.findTodayTasksByTaskUsu(taskUsu);
		return new ArrayList<>(tasks);
	}

	public ArrayList<Task> getWeekTasksByTaskUsu(Integer taskUsu) {
		Calendar cal = Calendar.getInstance();
		cal.setFirstDayOfWeek(Calendar.MONDAY);

		Date today = new Date();

		cal.setTime(today);
		cal.set(Calendar.DAY_OF_WEEK, Calendar.MONDAY);
		Date startOfWeek = cal.getTime();

		cal.set(Calendar.DAY_OF_WEEK, Calendar.SUNDAY);
		cal.add(Calendar.DATE, 1);
		Date endOfWeek = cal.getTime();

		return new ArrayList<>(taskRepository.findWeekTasksByTaskUsu(taskUsu, startOfWeek, endOfWeek));
	}

	public List<Task> getMonthTasksByTaskUsu(Integer taskUsu) {
		Calendar cal = Calendar.getInstance();
		int currentMonth = cal.get(Calendar.MONTH + 1);
		return new ArrayList<>(taskRepository.findMonthTasksByTaskUsu(taskUsu, currentMonth));
	}
	
	public void deleteTask(Integer taskId) {
		this.taskRepository.deleteById(taskId);
	}
}