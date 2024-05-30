package com.doit.CRUD.Controller;

import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.doit.CRUD.Model.Task;
import com.doit.CRUD.service.TaskService;
@CrossOrigin(origins = "https://doitwebsite.netlify.app")
@RestController
@RequestMapping("tasks")
public class TaskController {

	@Autowired
	TaskService taskService;

	@GetMapping
	public List<Task> getTasks() {
		return taskService.getTasks();
	}
	@GetMapping(path = "/n/{id}")
	public Optional<Task> getTask(@PathVariable Integer id) {
		return taskService.getTask(id);
	}
	@GetMapping(path = "/{id}")
	public List<Task> getUsuTasks(@PathVariable Integer id) {
		return taskService.getTaskByTaskUsu(id);
	}
	
    @GetMapping("/today/{taskUsu}")
    public List<Task> getTodayTasks(@PathVariable Integer taskUsu) {
        return taskService.getTodayTasksByTaskUsu(taskUsu);
    }

    @GetMapping("/week/{taskUsu}")
    public List<Task> getWeekTasks(@PathVariable Integer taskUsu) {
        return taskService.getWeekTasksByTaskUsu(taskUsu);
    }

    @GetMapping("/month/{taskUsu}")
    public List<Task> getMonthTasks(@PathVariable Integer taskUsu) {
        return taskService.getMonthTasksByTaskUsu(taskUsu);
    }
	
	@PostMapping("/new/{idUser}")
	public Task saveTask(@RequestBody Task task, @PathVariable Integer idUser) {
		if (task.getTASK_DATE() == null) {
			task.setTASK_DATE(new Date());
		}
		return taskService.saveTask(task, idUser);
	}

	@PutMapping("/{id}")
	public Task updateTaskById(@PathVariable Integer id, @RequestBody Task task) {
		return taskService.updateTaskById(task, id);
	}

	@PutMapping("/{idTask}/do")
	public Task doTask(@PathVariable Integer idTask) {
		return taskService.doTask(idTask);
	}
	@DeleteMapping("/{idTask}")
	public void deleteTask(@PathVariable Integer idTask) {
		taskService.deleteTask(idTask);
	}
}
