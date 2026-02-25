package com.rackleet.authserver.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

// First type param is the annotation, second is the type of the field being validated
public class PasswordValidator implements ConstraintValidator<ValidPassword, String>{
    
    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null || password.isBlank()) {
            return false; // @NotBlank handles the message for this case
        }

        /** 
         * Disable default constraint violation becuase I am adding multiple specific messages instead of one generic one.
         * Without disabling the user would see the generic message plus the specific ones.
        */
        context.disableDefaultConstraintViolation();
        boolean valid = true;

        if (password.length() < 12) {
            addViolation(context, "Password must be at least 12 characters");
            valid = false;
        }

        /** Why a max length of 128?
         * Bcrypt has a 72-byte input limit — anything beyond that gets silently truncated.
         * 128 characters is generous for usability but prevents someone from submitting a 10MB password as a denial-of-service attack 
         * (bcrypt is intentionally slow, so hashing a massive string ties up your CPU).
         */
        if (password.length() > 128) {
            addViolation(context, "Password must not exceed 128 characters");
            valid = false;
        }

        if (!password.matches(".*[A-Z].*")) {
            addViolation(context, "Password must contain at least one uppercase letter");
            valid = false;
        }

        if (!password.matches(".*[a-z].*")) {
            addViolation(context, "Password must contain at least one lowercase letter");
            valid = false;
        }

        if (!password.matches(".*[0-9].*")) {
            addViolation(context, "Password must contain at least one digit");
            valid = false;
        }

        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*")) {
            addViolation(context, "Password must contain at least one special character");
            valid = false;
        }

        return valid;
    }

    private void addViolation(ConstraintValidatorContext context, String message) {
        context.buildConstraintViolationWithTemplate(message)
            .addConstraintViolation();
    }
}
