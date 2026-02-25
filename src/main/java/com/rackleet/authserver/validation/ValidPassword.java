package com.rackleet.authserver.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = PasswordValidator.class) // Links this annotation to its validation logic
@Target({ElementType.FIELD}) // Can only be placed on fields, not classes or methods
@Retention(RetentionPolicy.RUNTIME) // Annotation survives to runtime so the validator can read it
public @interface ValidPassword {
    
    String message() default "Password does not meet complexity requirements";

    // Required by the Bean Validation spec - allows grouping validations
    Class<?>[] groups() default{};

    // Required by the Bean Validation spec - allows attaching metadata to a constraint
    Class<? extends Payload>[] payload() default {}; 
}
