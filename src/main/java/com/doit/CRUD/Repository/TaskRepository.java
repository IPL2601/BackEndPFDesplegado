package com.doit.CRUD.Repository;

import java.util.Date;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.doit.CRUD.Model.Task;
@Repository
public interface TaskRepository extends JpaRepository<Task, Integer>{

	@Query("SELECT t FROM Task t WHERE t.TASK_USU = :taskUsu AND DATE(t.TASK_DATE) = CURRENT_DATE()")
    List<Task> findTodayTasksByTaskUsu(@Param("taskUsu") Integer taskUsu);
	
	@Query("SELECT t FROM Task t WHERE t.TASK_USU = :taskUsu AND t.TASK_DATE BETWEEN :startOfWeek AND :endOfWeek")
    List<Task> findWeekTasksByTaskUsu(@Param("taskUsu") Integer taskUsu,
                                      @Param("startOfWeek") Date startOfWeek,
                                      @Param("endOfWeek") Date endOfWeek);

    @Query("SELECT t FROM Task t WHERE t.TASK_USU = :taskUsu AND FUNCTION('MONTH', t.TASK_DATE) = :currentMonth")
    List<Task> findMonthTasksByTaskUsu(@Param("taskUsu") Integer taskUsu,
                                      @Param("currentMonth") int currentMonth);
}
