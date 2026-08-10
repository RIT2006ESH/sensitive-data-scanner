package com.yourorg.scanner.detector;

import com.yourorg.scanner.model.SensitiveDataType;

import java.util.List;



public interface SensitiveDataDetector {

    SensitiveDataType getType();

    List<String> detectCandidates(String text);
}