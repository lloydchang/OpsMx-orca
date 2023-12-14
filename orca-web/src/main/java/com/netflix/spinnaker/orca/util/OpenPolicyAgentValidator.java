/*
 * Copyright 2023 OpsMx, Inc.
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

package com.netflix.spinnaker.orca.util;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.netflix.spinnaker.kork.web.exceptions.ValidationException;
import java.io.IOException;
import java.util.*;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class OpenPolicyAgentValidator {

  private static final String RESULT = "result";
  private static final String STATUS = "status";
  private static final String POLICY_PATH = "POLICY_PATH";

  @Value("${policy.opa.runtime.enabled:false}")
  private boolean isRuntimeEnabled;

  @Value("${policy.opa.url:http://opa:8181}")
  private String opaUrl;

  @Value("${policy.opa.resultKey:deny}")
  private String opaResultKey;

  @Value("${policy.opa.policyLocation:/v1/data/POLICY_PATH}")
  private String opaPolicyLocation;

  @Value("${policy.opa.enabled:false}")
  private boolean isOpaEnabled;

  @Value("${policy.opa.proxy:true}")
  private boolean isOpaProxy;

  @Value("${policy.opa.runtime.pipeline:}")
  private String runtimePolicies;

  private final Gson gson = new Gson();

  /* OPA spits JSON */
  private final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
  private final OkHttpClient opaClient = new OkHttpClient();

  public void validate(Map<String, Object> pipeline) {
    log.debug("Start of the Policy Validation");
    if (!isOpaEnabled) {
      log.info("OPA not enabled, returning");
      log.debug("End of the Policy Validation");
      return;
    }
    if (!isRuntimeEnabled) {
      log.info("OPA Runtime Policy validation not enabled, returning");
      log.debug("End of the Policy Validation");
      return;
    }
    String finalInput = "{}";
    int statusCode = 200;
    try {
      // Form input to opa
      finalInput = getOpaInput(pipeline);

      log.debug("Verifying {} with OPA", finalInput);

      /* build our request to OPA */
      RequestBody requestBody = RequestBody.create(JSON, finalInput);
      String opaFinalUrl =
          String.format(
              "%s/%s",
              opaUrl.endsWith("/") ? opaUrl.substring(0, opaUrl.length() - 1) : opaUrl,
              opaPolicyLocation.startsWith("/")
                  ? opaPolicyLocation.substring(1)
                  : opaPolicyLocation);

      log.debug("OPA endpoint : {}", opaFinalUrl);
      String opaStringResponse = "{}";

      if (runtimePolicies.isEmpty()) {
        statusCode = 200;
      } else {
        List<String> policyList = getRuntimePolicies();
        for (String policy : policyList) {
          opaFinalUrl = opaFinalUrl.replace(POLICY_PATH, policy);
          log.debug("opaFinalUrl: {}", opaFinalUrl);
          Map<String, Object> responseObject = doPost(opaFinalUrl, requestBody);
          opaStringResponse = String.valueOf(responseObject.get(RESULT));
          statusCode = Integer.valueOf(responseObject.get(STATUS).toString());
          log.debug("OPA response: {}", opaStringResponse);
          log.debug(
              "proxy enabled : {}, statuscode : {}, opaResultKey : {}",
              isOpaProxy,
              statusCode,
              opaResultKey);
          validateOPAResponse(opaStringResponse, statusCode);
        }
      }

    } catch (IOException e) {
      log.error("Communication exception for OPA at {}: {}", this.opaUrl, e.toString());
      log.debug("End of the Policy Validation");
      throw new ValidationException(e.toString(), null);
    }
    log.debug("End of the Policy Validation");
  }

  private void validateOPAResponse(String opaStringResponse, int statusCode) {
    if (isOpaProxy) {
      if (statusCode == 401) {
        JsonObject opaResponse = gson.fromJson(opaStringResponse, JsonObject.class);
        StringBuilder denyMessage = new StringBuilder();
        extractDenyMessage(opaResponse, denyMessage);
        if (StringUtils.isNotBlank(denyMessage)) {
          throw new ValidationException(denyMessage.toString(), null);
        } else {
          throw new ValidationException(
              "There is no '" + opaResultKey + "' field in the OPA response", null);
        }
      } else if (statusCode != 200) {
        throw new ValidationException(opaStringResponse, null);
      }
    } else {
      if (statusCode == 401) {
        JsonObject opaResponse = gson.fromJson(opaStringResponse, JsonObject.class);
        StringBuilder denyMessage = new StringBuilder();
        extractDenyMessage(opaResponse, denyMessage);
        if (StringUtils.isNotBlank(denyMessage)) {
          throw new ValidationException(denyMessage.toString(), null);
        } else {
          throw new ValidationException(
              "There is no '" + opaResultKey + "' field in the OPA response", null);
        }
      } else if (statusCode != 200) {
        throw new ValidationException(opaStringResponse, null);
      }
    }
  }

  private List<String> getRuntimePolicies() {
    if (runtimePolicies.contains(",")) {
      return Arrays.asList(runtimePolicies.split(",", -1));
    } else {
      List<String> policies = new ArrayList<>();
      policies.add(runtimePolicies);
      return policies;
    }
  }

  private void extractDenyMessage(JsonObject opaResponse, StringBuilder messagebuilder) {
    Set<Map.Entry<String, JsonElement>> fields = opaResponse.entrySet();
    fields.forEach(
        field -> {
          if (field.getKey().equalsIgnoreCase(opaResultKey)) {
            JsonArray resultKey = field.getValue().getAsJsonArray();
            if (resultKey.size() != 0) {
              resultKey.forEach(
                  result -> {
                    if (StringUtils.isNotEmpty(messagebuilder)) {
                      messagebuilder.append(", ");
                    }
                    messagebuilder.append(result.getAsString());
                  });
            }
          } else if (field.getValue().isJsonObject()) {
            extractDenyMessage(field.getValue().getAsJsonObject(), messagebuilder);
          } else if (field.getValue().isJsonArray()) {
            field
                .getValue()
                .getAsJsonArray()
                .forEach(
                    obj -> {
                      extractDenyMessage(obj.getAsJsonObject(), messagebuilder);
                    });
          }
        });
  }

  private String getOpaInput(Map<String, Object> pipeline) {
    String application;
    String pipelineName;
    String finalInput = null;
    JsonObject newPipeline = pipelineToJsonObject(pipeline);
    if (newPipeline.has("application")) {
      application = newPipeline.get("application").getAsString();
      pipelineName = newPipeline.get("name").getAsString();
      log.debug("## application : {}, pipelineName : {}", application, pipelineName);

      finalInput = gson.toJson(addWrapper(addWrapper(newPipeline, "pipeline"), "input"));
    } else {
      throw new ValidationException("The received pipeline doesn't have application field", null);
    }
    return finalInput;
  }

  private JsonObject addWrapper(JsonObject pipeline, String wrapper) {
    JsonObject input = new JsonObject();
    input.add(wrapper, pipeline);
    return input;
  }

  private JsonObject pipelineToJsonObject(Map<String, Object> pipeline) {
    String pipelineStr = gson.toJson(pipeline);
    return gson.fromJson(pipelineStr, JsonObject.class);
  }

  private Map<String, Object> doPost(String url, RequestBody requestBody) throws IOException {
    Request req = (new Request.Builder()).url(url).post(requestBody).build();
    return getOPAResponse(url, req);
  }

  private Map<String, Object> getOPAResponse(String url, Request req) throws IOException {
    Map<String, Object> apiResponse = new HashMap<>();
    Response httpResponse = this.opaClient.newCall(req).execute();
    String response = httpResponse.body().string();
    if (response == null) {
      throw new IOException("Http call yielded null response!! url:" + url);
    }
    apiResponse.put(RESULT, response);
    log.debug("## OPA Server response: {}", response);
    JsonObject responseJson = gson.fromJson(response, JsonObject.class);
    if (!responseJson.has(RESULT)) {
      // No "result" field? It could be due to incorrect policy path
      log.error("No 'result' field in the response - {}. OPA api - {}", response, req);
      apiResponse.put(STATUS, HttpStatus.BAD_REQUEST.value());
      return apiResponse;
    }
    JsonObject resultJson = responseJson.get(RESULT).getAsJsonObject();
    apiResponse.put(RESULT, gson.toJson(resultJson));
    log.debug("## resultJson : {}", resultJson);
    if (!resultJson.has("deny")) {
      // No "deny" field? that's weird
      log.error("No 'deny' field in the response - {}. OPA api - {}", response, req);
      apiResponse.put(STATUS, HttpStatus.BAD_REQUEST.value());
      return apiResponse;
    }
    if (resultJson.get("deny").getAsJsonArray().size() > 0) {
      apiResponse.put(STATUS, HttpStatus.UNAUTHORIZED.value());
    } else {
      // Number of denies are zero
      apiResponse.put(STATUS, HttpStatus.OK.value());
    }
    return apiResponse;
  }
}
