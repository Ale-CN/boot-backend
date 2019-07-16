package com.zw.admin.server.controller;

import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/test")
public class TestController {

    @GetMapping
    public String testGet(HttpServletRequest request){
        String name = request.getHeader("name");
        System.out.println("name = "+name);
        return "get";
    }

    @PostMapping
    public String testPost(HttpServletRequest request){
        return "post";
    }

    @PutMapping
    public String testPut(){
        return "put";
    }

    @DeleteMapping
    public String testDelete(){
        return "delete";
    }


}
