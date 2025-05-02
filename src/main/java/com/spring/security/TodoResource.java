package com.spring.security;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TodoResource {

    private static final List<Todo> TODOS_LIST = List.of(new Todo("user1", "Java_instructor"),
            new Todo("user2", " Python_instructor"));

    @GetMapping("/todos")
    public List<Todo> getAllTodos() {
        return TODOS_LIST;
    }

    @GetMapping("/users/{username}/todos")
    public Todo getTodoForUser(@PathVariable String username) {
        return TODOS_LIST.get(0);
    }
}

record Todo(String username, String description) {
}
