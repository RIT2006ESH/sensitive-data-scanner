package com.yourorg.scanner.detector;

import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class DetectorRegistry {

    private final List<SensitiveDataDetector> detectors;

    public DetectorRegistry(List<SensitiveDataDetector> detectors) {
        this.detectors = detectors;
    }

    public List<SensitiveDataDetector> getDetectors() {
        return detectors;
    }
}