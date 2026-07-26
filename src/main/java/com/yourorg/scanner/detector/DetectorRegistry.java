package com.yourorg.scanner.detector;

import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Holds every active SensitiveDataDetector and runs a piece of text through
 * all of them. Spring automatically collects every @Component that
 * implements SensitiveDataDetector into this list — adding a new detector
 * class means it's picked up here with zero wiring changes.
 */
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