package com.sslanalyzer.ssl_analyzer.controller;

import com.sslanalyzer.ssl_analyzer.model.SSLResult;
import com.sslanalyzer.ssl_analyzer.service.SSLAnalyzerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class SSLController {

    @Autowired
    private SSLAnalyzerService service;

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @PostMapping("/analyze")
    public String analyze(@RequestParam("hostname") String hostname, Model model) {
        SSLResult result = service.analyze(hostname);
        model.addAttribute("hostname", hostname);
        model.addAttribute("result", result);
        return "result";
    }
}
