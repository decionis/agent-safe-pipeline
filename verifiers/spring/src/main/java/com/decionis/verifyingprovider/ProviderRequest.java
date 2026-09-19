package com.decionis.verifyingprovider;

import java.util.Map;

/**
 * What the provider received. Header names are lower case; a covered header
 * received more than once is a refusal and must not be collapsed into this
 * map. {@code body} is null when the request carried none.
 */
public record ProviderRequest(String method, String path, byte[] body, Map<String, String> headers) {}
