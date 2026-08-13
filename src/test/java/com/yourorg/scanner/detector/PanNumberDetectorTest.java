package com.yourorg.scanner.detector;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PanNumberDetectorTest {

    private final PanNumberDetector detector = new PanNumberDetector();

    @Test
    void detectsValidPanWithIndividualCode() {
        List<String> results = detector.detectCandidates("PAN: ABCPK1234L on file.");
        assertEquals(1, results.size());
        assertEquals("ABCPK1234L", results.get(0));
    }

    @Test
    void detectsValidPanWithCompanyCode() {
        List<String> results = detector.detectCandidates("ABCCK1234L");
        assertEquals(1, results.size());
    }

    @Test
    void doesNotMatchInvalidHolderTypeCode() {
        List<String> results = detector.detectCandidates("ABCDE1234F");
        assertTrue(results.isEmpty());
    }

    @Test
    void doesNotMatchWrongLetterCount() {
        List<String> results = detector.detectCandidates("ABCDEFG5678F");
        assertTrue(results.isEmpty());
    }

    @Test
    void doesNotMatchLowercase() {
        List<String> results = detector.detectCandidates("abcpk1234l");
        assertTrue(results.isEmpty());
    }
}
