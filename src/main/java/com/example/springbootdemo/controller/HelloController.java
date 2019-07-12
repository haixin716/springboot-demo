package com.example.springbootdemo.controller;

import java.util.HashMap;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

	@RequestMapping("/hello")
	public String index() {
		return "Hello World";
	}
	
	@RequestMapping("/demo")
	public String demo() {
		return "This is Springboot Demo!";
	}
	
	@RequestMapping("/json")
	public HashMap<String, Object> json(){
		HashMap<String, Object> map = new HashMap<String, Object>();
		map.put("key", "value");
		return map;
	}
}
