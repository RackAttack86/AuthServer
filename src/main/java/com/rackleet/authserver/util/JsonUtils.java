package com.rackleet.authserver.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;


public class JsonUtils {
    
    private static final ObjectMapper mapper = new ObjectMapper();
    
    public static String toJson(List<String> list) {
        try {
            return mapper.writeValueAsString(list != null ? list : List.of());
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize list to JSON", e);
        }
    }

    public static List<String> fromJson(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            return mapper.readValue(json, new TypeReference<List<String>>() {
            });
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to deserialize JSON to list", e);
        }
    }
}
