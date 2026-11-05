class VerifyRequestContext {
  VerifyRequestContext({
    required this.body,
    required Map<String, String> headers,
  }) : headers = Map<String, String>.unmodifiable(headers);

  final String body;
  final Map<String, String> headers;
}
