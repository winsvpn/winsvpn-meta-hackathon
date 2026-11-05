from pathlib import Path
import argparse
import os
import subprocess
import tempfile

parser = argparse.ArgumentParser(description="Offline Swift health fixtures; no provider or native archive")
parser.add_argument("--swiftc", default="/usr/bin/swiftc")
parser.add_argument("--output-dir", required=True, type=Path)
args = parser.parse_args()
src = Path(__file__).resolve().parents[1]
p = args.output_dir.resolve()
p.mkdir(parents=True, exist_ok=False)
s=(src/'apple/WinsTunnelCore/WinsPacketTunnelEngine.swift').read_text()
def block(text,marker):
 start=text.index(marker); brace=text.index('{',start); depth=1; i=brace+1
 # Braces in these complete declarations are balanced, including comments/strings.
 while depth:
  if text[i]=='{':depth+=1
  if text[i]=='}':depth-=1
  i+=1
 return text[start:i]
parts=['import Foundation\nimport CoreFoundation\nimport CryptoKit\n']
for marker in ['final class WinsTunnelOperationGate {','struct WinsPacketTunnelProviderAppMessage {','enum WinsPacketTunnelEngineRuntimeStatus {','extension WinsPacketTunnelEngineRuntimeStatus {','enum WinsWinnSeamObservabilitySample {']:
 parts.append(block(s,marker))
parts.append('struct WinsPacketTunnelEnginePlan { var statusFields: [String: Any] = [:] }')
# healthSnapshot's lifecycle verdict (Round A3) and the published host keys the
# sampler lists live in the host contract file: extract those declarations too.
c=(src/'apple/WinsTunnelCore/WinsWinn3HostContract.swift').read_text()
for marker in ['enum WinsWinn3Lifecycle {','enum WinsWinn3RecoveryCeiling {','final class WinsWinn3LifecycleHistory {','final class WinsWinn3RecoveryClock {']:
 parts.append(block(c,marker))
for platform,name in [('ios','IOSFixture'),('macos','MacFixture')]:
 text=(src/f'{platform}/PacketTunnel/PacketTunnelProvider.swift').read_text()
 method=block(text,'  override func handleAppMessage(')
 assert method.count('standaloneDatapath?.healthSnapshot()')==1
 assert method.count('lifecycleGate.withLock {') == 1
 assert method.index('bundleExecutableSHA256(.main)') < method.index('lifecycleGate.withLock {')
 assert 'let statusGeneration = currentStatusGeneration()' in method
 assert 'statusGeneration: statusGeneration' in method
 assert 'statusFields["status_generation"] = statusGeneration' in method
 assert 'statusFields.removeValue(forKey: "status_generation")' in method
 assert method.index('return message.responseData') < method.index('completionHandler?(responseData)')
 assert 'lifecycleGate.begin' not in method and 'lifecycleGate.invalidate' not in method
 assert 'engineRunning: engineRunning' in method and 'let appMessageReady = engineRunning && message.accepted' in method
 assert 'engineReady: appMessageReady' in method and 'networkSettingsReady: appMessageReady' in method
 for forbidden in ['releaseTunnelNetworkSettings(', 'cancelTunnelWithError(', 'stopTunnel(', '.stop()']:
  assert forbidden not in method
 parts.append(f'final class {name}: ProviderFixture {{\n'+method+'\n}')
(p/'Derived.swift').write_text('\n\n'.join(parts)+'\n')
print('extracted complete actual sampler/filter/app-message declarations and both actual callback methods')

env = os.environ.copy()
env["CLANG_MODULE_CACHE_PATH"] = str(p / "clang-cache")
command = [args.swiftc, "-swift-version", "5", "-module-cache-path", str(p / "swift-cache"),
           str(src / "apple/WinsTunnelCore/WinsWinn3Datapath.swift"), str(p / "Derived.swift"),
           str(src / "tools/apple_runtime_health/main.swift"), "-o", str(p / "health-tests")]
subprocess.run(command, env=env, check=True, timeout=120)
for name in ["completed", "live", "missing", "unavailable", "legacy", "receive_failure"]:
    subprocess.run([str(p / "health-tests"), name], env=env, check=True, timeout=10)
