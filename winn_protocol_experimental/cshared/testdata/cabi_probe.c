/* C ABI probe for package cshared. Compiled and exec'd by winn_clientbinding_test.go.
   Declares the surface itself so the check does not depend on the generated header. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void WinnFreeString(char *value);
extern char *WinnFacadeVersion(void);
extern char *WinnProtocolVersion(void);
extern char *WinnRekeyProtocolVersion(void);
extern int WinnTunnelSupported(void);
extern char *WinnTunnelBackendJSON(void);
extern char *WinnSupportedSuitesJSON(void);
extern char *WinnSupportedModesJSON(void);
extern char *WinnCapabilitiesJSON(char *suite, char **errorOut);
extern char *WinnRequiredAuthAlgorithm(char *suite, char **errorOut);
extern char *WinnCarriersForModeJSON(char *mode, char **errorOut);
extern char *WinnValidateReadinessJSON(char *document);
extern char *WinnValidateBindingJSON(char *document);
extern char *WinnValidateDeviceID(char *value);
extern char *WinnValidatePeerPublicKey(char *value);
extern char *WinnConnect(char *requestJSON, char **errorOut);
extern char *WinnStatusJSON(void);
extern char *WinnDisconnect(void);

static int fails;

static void pass(const char *name) {
	printf("PASS %s\n", name);
}

static void fail(const char *name, const char *detail) {
	fprintf(stderr, "FAIL %s: %s\n", name, detail);
	fails++;
}

static int contains(const char *s, const char *needle) {
	return s != NULL && needle != NULL && strstr(s, needle) != NULL;
}

int main(void) {
	WinnFreeString(NULL);
	pass("WinnFreeString(NULL)");

	char *facade = WinnFacadeVersion();
	char *protocol = WinnProtocolVersion();
	char *rekey = WinnRekeyProtocolVersion();
	if (facade == NULL || facade[0] == '\0') {
		fail("WinnFacadeVersion", "NULL or empty");
	} else {
		pass("WinnFacadeVersion");
	}
	if (protocol == NULL || protocol[0] == '\0') {
		fail("WinnProtocolVersion", "NULL or empty");
	} else {
		pass("WinnProtocolVersion");
	}
	if (rekey == NULL || rekey[0] == '\0') {
		fail("WinnRekeyProtocolVersion", "NULL or empty");
	} else {
		pass("WinnRekeyProtocolVersion");
	}
	if (protocol != NULL && rekey != NULL && strcmp(protocol, rekey) == 0) {
		fail("versions_distinct", "ProtocolVersion equals RekeyProtocolVersion");
	} else {
		pass("versions_distinct");
	}
	WinnFreeString(facade);
	WinnFreeString(protocol);
	WinnFreeString(rekey);

	int supported = WinnTunnelSupported();
	if (supported != 0 && supported != 1) {
		fail("WinnTunnelSupported", "not 0 or 1");
	} else {
		pass("WinnTunnelSupported_boolean");
	}
	if (supported != 0) {
		fail("WinnTunnelSupported_no_engine", "want 0 with WINS_WINN3_ENGINE unset");
	} else {
		pass("WinnTunnelSupported_no_engine");
	}

	char *status = WinnStatusJSON();
	if (status == NULL) {
		fail("WinnStatusJSON", "NULL");
	} else if (!contains(status, "state")) {
		fail("WinnStatusJSON", "missing state");
	} else {
		pass("WinnStatusJSON");
	}
	WinnFreeString(status);

	char *backend = WinnTunnelBackendJSON();
	if (backend == NULL || !contains(backend, "safe_to_advertise_protocol")) {
		fail("WinnTunnelBackendJSON", "NULL or missing advertise field");
	} else if (contains(backend, "\"safe_to_advertise_protocol\":true")) {
		fail("WinnTunnelBackendJSON", "advertises protocol with no engine");
	} else {
		pass("WinnTunnelBackendJSON");
	}
	WinnFreeString(backend);

	char *suites = WinnSupportedSuitesJSON();
	char *modes = WinnSupportedModesJSON();
	if (suites == NULL || suites[0] != '[') {
		fail("WinnSupportedSuitesJSON", "not a JSON array");
	} else {
		pass("WinnSupportedSuitesJSON");
	}
	if (modes == NULL || modes[0] != '[') {
		fail("WinnSupportedModesJSON", "not a JSON array");
	} else {
		pass("WinnSupportedModesJSON");
	}
	WinnFreeString(suites);
	WinnFreeString(modes);

	char *err = (char *)0x1;
	char *got = WinnConnect(NULL, &err);
	if (got != NULL) {
		fail("WinnConnect(NULL)", "non-NULL result");
		WinnFreeString(got);
	} else {
		pass("WinnConnect(NULL)_result");
	}
	if (err == NULL || !contains(err, "NULL")) {
		fail("WinnConnect(NULL)_error", err == NULL ? "NULL errorOut" : err);
	} else {
		pass("WinnConnect(NULL)_error");
	}
	WinnFreeString(err);

	got = WinnConnect(NULL, NULL);
	if (got != NULL) {
		fail("WinnConnect(NULL,errorOut=NULL)", "synthesized a result");
		WinnFreeString(got);
	} else {
		pass("WinnConnect(NULL,errorOut=NULL)");
	}

	err = (char *)0x1;
	got = WinnConnect("", &err);
	if (got != NULL) {
		fail("WinnConnect(empty)", "non-NULL result");
		WinnFreeString(got);
	} else {
		pass("WinnConnect(empty)_result");
	}
	if (err == NULL || err[0] == '\0') {
		fail("WinnConnect(empty)_error", "missing error");
	} else if (contains(err, "NULL")) {
		fail("WinnConnect(empty)_error", "empty string reported as NULL");
	} else {
		pass("WinnConnect(empty)_error");
	}
	WinnFreeString(err);

	err = (char *)0x1;
	got = WinnConnect("{\"keys\":\"/x\",\"create\":{\"payload\":\"ip-packet\"}}", &err);
	if (got != NULL) {
		fail("WinnConnect(no_engine)", "synthetic success");
		WinnFreeString(got);
	} else {
		pass("WinnConnect(no_engine)_result");
	}
	if (err == NULL || err[0] == '\0') {
		fail("WinnConnect(no_engine)_error", "NULL result and NULL error");
	} else {
		pass("WinnConnect(no_engine)_error");
	}
	WinnFreeString(err);

	got = WinnConnect("{\"keys\":\"/x\",\"create\":{\"payload\":\"ip-packet\"}}", NULL);
	if (got != NULL) {
		fail("WinnConnect(no_engine,errorOut=NULL)", "synthesized success");
		WinnFreeString(got);
	} else {
		pass("WinnConnect(no_engine,errorOut=NULL)");
	}

	err = (char *)0x1;
	got = WinnCapabilitiesJSON(NULL, &err);
	if (got != NULL) {
		fail("WinnCapabilitiesJSON(NULL)", "non-NULL result");
		WinnFreeString(got);
	} else {
		pass("WinnCapabilitiesJSON(NULL)_result");
	}
	if (err == NULL || !contains(err, "NULL")) {
		fail("WinnCapabilitiesJSON(NULL)_error", err == NULL ? "NULL errorOut" : err);
	} else {
		pass("WinnCapabilitiesJSON(NULL)_error");
	}
	WinnFreeString(err);

	err = (char *)0x1;
	got = WinnRequiredAuthAlgorithm(NULL, &err);
	if (got != NULL) {
		fail("WinnRequiredAuthAlgorithm(NULL)", "non-NULL result");
		WinnFreeString(got);
	} else {
		pass("WinnRequiredAuthAlgorithm(NULL)_result");
	}
	if (err == NULL || !contains(err, "NULL")) {
		fail("WinnRequiredAuthAlgorithm(NULL)_error", err == NULL ? "NULL errorOut" : err);
	} else {
		pass("WinnRequiredAuthAlgorithm(NULL)_error");
	}
	WinnFreeString(err);

	err = (char *)0x1;
	got = WinnCarriersForModeJSON(NULL, &err);
	if (got != NULL) {
		fail("WinnCarriersForModeJSON(NULL)", "non-NULL result");
		WinnFreeString(got);
	} else {
		pass("WinnCarriersForModeJSON(NULL)_result");
	}
	if (err == NULL || !contains(err, "NULL")) {
		fail("WinnCarriersForModeJSON(NULL)_error", err == NULL ? "NULL errorOut" : err);
	} else {
		pass("WinnCarriersForModeJSON(NULL)_error");
	}
	WinnFreeString(err);

	err = (char *)0x1;
	got = WinnCapabilitiesJSON("not-a-suite", &err);
	if (got != NULL) {
		fail("WinnCapabilitiesJSON(unknown)", "returned a list");
		WinnFreeString(got);
	} else {
		pass("WinnCapabilitiesJSON(unknown)_result");
	}
	if (err == NULL || err[0] == '\0') {
		fail("WinnCapabilitiesJSON(unknown)_error", "empty error");
	} else {
		pass("WinnCapabilitiesJSON(unknown)_error");
	}
	WinnFreeString(err);

	char *v = WinnValidateReadinessJSON(NULL);
	if (v == NULL || !contains(v, "NULL")) {
		fail("WinnValidateReadinessJSON(NULL)", v == NULL ? "NULL means success" : v);
	} else {
		pass("WinnValidateReadinessJSON(NULL)");
	}
	WinnFreeString(v);

	v = WinnValidateBindingJSON(NULL);
	if (v == NULL || !contains(v, "NULL")) {
		fail("WinnValidateBindingJSON(NULL)", v == NULL ? "NULL means success" : v);
	} else {
		pass("WinnValidateBindingJSON(NULL)");
	}
	WinnFreeString(v);

	v = WinnValidateDeviceID(NULL);
	if (v == NULL || !contains(v, "NULL")) {
		fail("WinnValidateDeviceID(NULL)", v == NULL ? "NULL means success" : v);
	} else {
		pass("WinnValidateDeviceID(NULL)");
	}
	WinnFreeString(v);

	v = WinnValidatePeerPublicKey(NULL);
	if (v == NULL || !contains(v, "NULL")) {
		fail("WinnValidatePeerPublicKey(NULL)", v == NULL ? "NULL means success" : v);
	} else {
		pass("WinnValidatePeerPublicKey(NULL)");
	}
	WinnFreeString(v);

	v = WinnValidateDeviceID("device-01");
	if (v != NULL) {
		fail("WinnValidateDeviceID(device-01)", v);
		WinnFreeString(v);
	} else {
		pass("WinnValidateDeviceID(device-01)");
	}

	v = WinnValidateDeviceID("bad id with spaces");
	if (v == NULL) {
		fail("WinnValidateDeviceID(spaces)", "accepted; NULL means success");
	} else {
		pass("WinnValidateDeviceID(spaces)");
		WinnFreeString(v);
	}

	v = WinnValidatePeerPublicKey("<REDACTED_WG_KEY>");
	if (v == NULL) {
		fail("WinnValidatePeerPublicKey(all_zero)", "accepted");
	} else {
		pass("WinnValidatePeerPublicKey(all_zero)");
		WinnFreeString(v);
	}

	(void)WinnDisconnect();
	v = WinnDisconnect();
	if (v == NULL) {
		fail("WinnDisconnect(no_session)", "NULL means success on this entry point");
	} else {
		pass("WinnDisconnect(no_session)");
		WinnFreeString(v);
	}

	if (fails != 0) {
		fprintf(stderr, "%d check(s) failed\n", fails);
		return 1;
	}
	printf("ALL_PASS\n");
	return 0;
}
