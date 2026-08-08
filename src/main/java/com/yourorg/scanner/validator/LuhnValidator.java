package com.yourorg.scanner.validator;

import org.springframework.stereotype.Component;

@Component
public class LuhnValidator {

    public boolean isValid(String rawCandidate) {
        String digitsOnly = stripNonDigits(rawCandidate);

        if (digitsOnly.length() < 13 || digitsOnly.length() > 19) {
            return false;
        }

        int sum = 0;
        boolean doubleDigit = false;

        for (int i = digitsOnly.length() - 1; i >= 0; i--) {
            int digit = digitsOnly.charAt(i) - '0';

            if (doubleDigit) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }

            sum += digit;
            doubleDigit = !doubleDigit;
        }

        return sum % 10 == 0;
    }

    private String stripNonDigits(String input) {
        return input == null ? "" : input.replaceAll("[^0-9]", "");
    }
}