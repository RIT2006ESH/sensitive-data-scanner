package com.yourorg.scanner.detector;

import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Indian Voter ID / EPIC: 3 letters + 7 digits. No public checksum. */
@Component
public class VoterIdDetector implements SensitiveDataDetector {

    private static final Pattern VOTER_ID_PATTERN = Pattern.compile("\\b[A-Z]{3}[0-9]{7}\\b");

    @Override
    public SensitiveDataType getType() { return SensitiveDataType.VOTER_ID; }

    @Override
    public List<String> detectCandidates(String text) {
        List<String> candidates = new ArrayList<>();
        if (text == null || text.isEmpty()) return candidates;
        Matcher matcher = VOTER_ID_PATTERN.matcher(text);
        while (matcher.find()) candidates.add(matcher.group());
        return candidates;
    }
}