package com.yourorg.scanner.dashboard;

import com.yourorg.scanner.config.AppProperties;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/api/scans")
public class AppConfigController {

    private final AppProperties appProperties;

    public AppConfigController(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    @GetMapping("/config")
    public AppProperties getConfig() {
        return appProperties;
    }
}