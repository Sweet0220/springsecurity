package com.example.securitydemo.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1,"Mircea Nealcos"),
            new Student(2,"Calin Nealcos"),
            new Student(3, "Daiana Nealcos")
    );

    @GetMapping(path = "{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId) {
        return STUDENTS.stream().filter(student -> studentId.equals(student.getStudentId())).findAny().orElseThrow(
                () -> new IllegalStateException("Student " + studentId + "does not exist!")
        );
    }
}
