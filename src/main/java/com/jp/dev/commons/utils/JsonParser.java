package com.jp.dev.commons.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.springframework.lang.NonNull;

public class JsonParser {

  private static final ObjectMapper mapper;

  public JsonParser() throws InstantiationException {
    throw new InstantiationException("util class");
  }

  static {
    mapper = new ObjectMapper();
    mapper.registerModule(new JavaTimeModule())
        .registerModule(new ParameterNamesModule())
        .registerModule(new Jdk8Module())
        .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
  }

  public static String toJson(@NonNull Object object) throws JsonProcessingException {
    return mapper.writeValueAsString(object);
  }

  public static <T> T toObject(@NonNull String object, Class<T> clazz)
      throws JsonProcessingException {

    try {
      return mapper.readValue(object, clazz);
    } catch (IllegalArgumentException ex) {
      Logger.getLogger(JsonParser.class.getName())
          .log(Level.WARNING, String.format("Error parsing to json: %s", object));
      throw ex;
    }
  }
}