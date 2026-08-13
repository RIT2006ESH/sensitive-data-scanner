package com.yourorg.scanner.detector;

import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds candidate PAN numbers matching the real Indian Income Tax
 * Department structure: AAAA A 9999 A, where:
 *   - positions 1-3: any letters
 *   - position 4: holder-type code, restricted to the actual valid set
 *     (A=AOP, B=BOI, C=Company, F=Firm, G=Government, H=HUF,
 *      J=Artificial Judicial Person, L=Local Authority, P=Individual,
 *      T=Trust) -- any other letter here structurally cannot be a real
 *      PAN, so this alone eliminates most random-string false positives
 *      that merely happen to match the loose "5 letters + 4 digits + 1
 *      letter" shape.
 *   - position 5: first letter of surname/entity name (unrestricted)
 *   - positions 6-9: digits
 *   - position 10: check letter (unrestricted at detection time)
 */
@Component
public class PanNumberDetector implements SensitiveDataDetector {

    private static final Pattern PAN_PATTERN =
            Pattern.compile("\\b[A-Z]{3}[ABCFGHJLPT][A-Z]\\d{4}[A-Z]\\b");

    @Override
    public SensitiveDataType getType() {
        return SensitiveDataType.PAN_NUMBER;
    }

    @Override
    public List<String> detectCandidates(String text) {
        List<String> candidates = new ArrayList<>();
        if (text == null || text.isEmpty()) {
            return candidates;
        }

        Matcher matcher = PAN_PATTERN.matcher(text);
        while (matcher.find()) {
            candidates.add(matcher.group());
        }
        return candidates;
    }
}
