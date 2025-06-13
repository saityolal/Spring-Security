package com.spring.security;

import java.util.List;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import jakarta.annotation.security.RolesAllowed;

@RestController
@EnableMethodSecurity(jsr250Enabled = true)
public class TodoResource {

    private static final List<Todo> TODOS_LIST = List.of(new Todo("user1", "Java_instructor"),
            new Todo("user2", " Python_instructor"));

    @GetMapping("/todos")
    public List<Todo> getAllTodos() {
        return TODOS_LIST;
    }

    // @GetMapping("/users/{username}/todos")
    // // @PreAuthorize("hasRole('USER') or hasRole('ADMIN') and #username ==
    // authentication.name")
    // // @PostAuthorize("returnObject.username == 'user1'")
    // public Todo getTodoForUser(@PathVariable String username) {
    // return TODOS_LIST.get(0);
    // }
    @GetMapping("/users/{username}/todos")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') and #username == authentication.name")
    @PostAuthorize("returnObject.username == 'user1'") // if return object is user1 then, authorize.
    @RolesAllowed({"USER", "ADMIN"})
    @Secured( {"ROLE_USER", "ROLE_ADMIN"})
    public Todo getTodoForUser(@PathVariable(value = "username") String username) {
        return TODOS_LIST.stream().filter(todo -> todo.username().equals(username)).findFirst().orElse(null);
    }

}

record Todo(String username, String description) {
}
