/*
 * Copyright 2021 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.orca.applications.utils;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.netflix.spinnaker.fiat.model.Authorization;
import com.netflix.spinnaker.fiat.model.resources.Permissions;
import com.netflix.spinnaker.orca.front50.model.Application;
import groovy.util.logging.Slf4j;
import okhttp3.*;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

@Slf4j
@Component
public class ValidateRBAC {

  @Value("${policy.opa.url:http://oes-server-svc.oes:8085}")
  private String opaUrl;

  @Value("${policy.opa.resultKey:deny}")
  private String opaResultKey;

  @Value("${policy.opa.policyLocation:/v1/staticPolicy/eval}")
  private String opaPolicyLocation;

  @Value("${policy.opa.enabled:false}")
  private boolean isOpaEnabled;

  @Value("${policy.opa.proxy:true}")
  private boolean isOpaProxy;

  private final Gson gson = new Gson();

  /* OPA spits JSON */
  private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
  private final OkHttpClient opaClient = new OkHttpClient();

  private final Logger logger = LoggerFactory.getLogger(getClass());

   public String validatePolicy(Application application) {
    if (!isOpaEnabled) {
      logger.info("OPA not enabled, returning");
      return null;
    }
    Response httpResponse;

    try {
      String finalInput = getOpaInput(application);
      logger.info("Verifying {} with OPA", finalInput);

      RequestBody requestBody = RequestBody.create(JSON, finalInput);
      String opaFinalUrl = String.format("%s/%s", opaUrl.endsWith("/") ? opaUrl.substring(0, opaUrl.length() - 1) : opaUrl, opaPolicyLocation.startsWith("/") ? opaPolicyLocation.substring(1) : opaPolicyLocation);

      logger.debug("OPA endpoint : {}", opaFinalUrl);
      String opaStringResponse;

      /* fetch the response from the spawned call execution */
      httpResponse = doPost(opaFinalUrl, requestBody);
      opaStringResponse = httpResponse.body() != null ? httpResponse.body().string() : "";
      logger.info("OPA response: {}", opaStringResponse);
      if (isOpaProxy) {
        if (httpResponse.code() == 401 ) {
          JsonObject opaResponse = gson.fromJson(opaStringResponse, JsonObject.class);
          StringBuilder denyMessage = new StringBuilder();
          extractDenyMessage(opaResponse, denyMessage);
          String opaMessage = denyMessage.toString();
          if (StringUtils.isNotBlank(opaMessage)) {
            return opaMessage;
          } else {
            return "Application doesn't satisfy the policy specified";
          }
        } else if (httpResponse.code() != 200 ) {
          return "Policy validation failed with status code" + httpResponse.code();
        }
      }

    } catch (Exception e) {
      logger.error("Communication exception for OPA at {}: {}", this.opaUrl, e.toString());
      return "Policy validation failed with exception, Please check OPA server running";
    }

    return null;
  }

  private void extractDenyMessage(JsonObject opaResponse, StringBuilder messagebuilder) {
    Set<Map.Entry<String, JsonElement>> fields = opaResponse.entrySet();
    fields.forEach(field -> {
      if (field.getKey().equalsIgnoreCase(opaResultKey)) {
        JsonArray resultKey = field.getValue().getAsJsonArray();
        if (resultKey.size() != 0) {
          resultKey.forEach(result -> {
            if (StringUtils.isNotEmpty(messagebuilder)) {
              messagebuilder.append(", ");
            }
            messagebuilder.append(result.getAsString());
          });
        }
      }else if (field.getValue().isJsonObject()) {
        extractDenyMessage(field.getValue().getAsJsonObject(), messagebuilder);
      } else if (field.getValue().isJsonArray()){
        field.getValue().getAsJsonArray().forEach(obj ->
          extractDenyMessage(obj.getAsJsonObject(), messagebuilder));
      }
    });
  }


  private String getOpaInput(Application application) {
    JsonObject applicationJson = applicationToJson(application);
    return gson.toJson(addWrapper(addWrapper(applicationJson, "new"), "input"));
  }

  private JsonObject applicationToJson(Application application) {

     JsonObject appObject = new JsonObject();
     appObject.addProperty("application", application.name);
     appObject.addProperty("email", application.email);

     JsonObject permission = new JsonObject();
     Set<Authorization> allPermisions = EnumSet.allOf( Authorization.class );
     if (application.getPermission() != null) {
       Permissions permissions = application.getPermission().getPermissions();
       if (permissions != null) {
         allPermisions.forEach(auth -> {
           JsonArray roles = new  JsonArray();
           permissions.get(auth).forEach(role -> {
             roles.add(role);
           });
           permission.add(auth.name(), roles);
         });
       }  else {
         allPermisions.forEach(auth -> {
           permission.add(auth.name(), new  JsonArray());
         });
       }
     }
     appObject.add("permissions", permission);
    String applicationStr = gson.toJson(appObject);
    return gson.fromJson(applicationStr, JsonObject.class);
  }

  private JsonObject addWrapper(JsonObject pipeline, String wrapper) {
    JsonObject input = new JsonObject();
    input.add(wrapper, pipeline);
    return input;
  }

  private Response doPost(String url, RequestBody requestBody) throws IOException {
    Request req = (new Request.Builder()).url(url).post(requestBody).build();
    return getResponse(url, req);
  }

  private Response getResponse(String url, Request req) throws IOException {
    Response httpResponse = this.opaClient.newCall(req).execute();
    ResponseBody responseBody = httpResponse.body();
    if (responseBody == null) {
      throw new IOException("Http call yielded null response!! url:" + url);
    }
    return httpResponse;
  }
}
