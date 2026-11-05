import Foundation
@main enum ProviderTests {
 static func awaitCondition(_ label:String,seconds:Double=4,_ condition:()->Bool){let until=Date().addingTimeInterval(seconds);while !condition(){precondition(Date()<until,label);Thread.sleep(forTimeInterval:0.01)}}
 static func querySuccess(){let callback=Harness.query.get()!;Harness.query.set(nil);callback(.success(Data(repeating:0,count:12)))}
 static func stop(_ p:NEDNSProxyProvider){let done=DispatchSemaphore(value:0);p.stopProxy(with:.userInitiated){done.signal()};precondition(done.wait(timeout:.now()+3) == .success)}
 static func main(){
  Harness.reset();let dns=DNSProxyProvider();let starts=Box<[Bool]>([])
  dns.startProxy(options:nil){e in starts.change{$0.append(e==nil)}}
  awaitCondition("first DNS query"){Harness.queryCount.get()==1};querySuccess()
  awaitCondition("DNS completion"){starts.get()==[true]}
  precondition(Harness.leaseCount.get()==0,"lease occurred before DNS completion")
  awaitCondition("second DNS probe"){Harness.queryCount.get()>=2};querySuccess()
  awaitCondition("running DNS lease"){Harness.leaseCount.get()==1};stop(dns)
  print("PASS DNS startup completes before later lease")
  Harness.reset();let late=DNSProxyProvider();let lateStarts=Box<[Bool]>([])
  late.startProxy(options:nil){e in lateStarts.change{$0.append(e==nil)}}
  awaitCondition("deadline query captured"){Harness.queryCount.get()==1}
  let callback=Harness.query.get()!;let client=Harness.client.get()!
  awaitCondition("25 second startup timeout",seconds:28){lateStarts.get()==[false]}
  precondition(client.cancelled.get());callback(.success(Data(repeating:0,count:12)))
  Thread.sleep(forTimeInterval:0.1);precondition(Harness.leaseCount.get()==0 && lateStarts.get()==[false]);stop(late)
  print("PASS DNS timeout cancels client and rejects late success")
  Harness.reset();let proxy=TransparentProxyProvider();let proxyStarts=Box<[Bool]>([])
  proxy.startProxy(options:nil){e in proxyStarts.change{$0.append(e==nil)}}
  awaitCondition("broker"){Harness.broker.get() != nil}
  let leased=Box(false);Harness.broker.get()!.readinessLease{leased.set($0)}
  awaitCondition("capture pending"){Harness.settings.get() != nil && leased.get()}
  Thread.sleep(forTimeInterval:6.2);Harness.settings.get()!(nil)
  awaitCondition("expired capture rejected"){proxyStarts.get()==[false]};stop(proxy)
  print("PASS delayed capture rejects expired DNS lease")
  Harness.reset();let failed=TransparentProxyProvider();let failureStarts=Box<[Bool]>([])
  failed.startProxy(options:nil){e in failureStarts.change{$0.append(e==nil)}}
  awaitCondition("second broker"){Harness.broker.get() != nil}
  Harness.broker.get()!.readinessLease{_ in};awaitCondition("second capture pending"){Harness.settings.get() != nil}
  precondition(Harness.published.get(),"broker port was not published while the broker listened")
  let settings=Harness.settings.get()!;Harness.runtime.get()!.stop()
  awaitCondition("engine failure"){failureStarts.get()==[false]};settings(nil)
  precondition(!Harness.published.get(),"broker port stayed published after the broker stopped")
  Thread.sleep(forTimeInterval:0.1);precondition(failureStarts.get()==[false]);stop(failed)
  print("PASS failed generation rejects late capture completion")
  Harness.reset();Harness.autoBridge.set(true)
  let togetherProxy=TransparentProxyProvider();let togetherDNS=DNSProxyProvider()
  let proxyUp=Box(false);let dnsUp=Box(false)
  togetherProxy.startProxy(options:nil){e in precondition(e==nil);proxyUp.set(true)}
  awaitCondition("coordinated broker"){Harness.broker.get() != nil}
  togetherDNS.startProxy(options:nil){e in precondition(e==nil);dnsUp.set(true)}
  awaitCondition("coordinated DNS start"){dnsUp.get()}
  precondition(!proxyUp.get())
  awaitCondition("coordinated capture request"){Harness.settings.get() != nil}
  Harness.settings.get()!(nil)
  awaitCondition("coordinated proxy startup"){proxyUp.get()}
  stop(togetherDNS);stop(togetherProxy)
  print("PASS coordinated DNS and transparent startup completes without dependency deadlock")
 }
}
