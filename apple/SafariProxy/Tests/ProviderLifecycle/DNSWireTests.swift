import Foundation
@main enum DNSWireTests {
 static func rejects(_ body: () throws -> Void) { do { try body(); fatalError("expected rejection") } catch {} }
 static func main() throws {
  for count in [65533,65534,65535] {
   let query=Data(repeating:0,count:count)
   let parts=try SafariDNSWire.tcpSegments(query)
   precondition(parts.count==2 && parts[0].count==2 && parts[1]==query && parts.allSatisfy{$0.count<=65535})
  }
  rejects { _=try SafariDNSWire.tcpSegments(Data(repeating:0,count:65536)) }
  var attack=Data(repeating:0,count:32768)
  attack[0]=0x80;attack[1]=0;attack[2]=0x80;attack[3]=0
  var partial=SafariDNSWire.TCPReply()
  let partialResult=try partial.append(attack)
  precondition(partialResult==nil)
  let completed=try partial.append(Data([0,0]))
  precondition(completed?.count==32768 && completed?[0]==0x80)
  rejects { _=try partial.append(Data([0])) }
  var bad=SafariDNSWire.TCPReply()
  rejects { _=try bad.append(Data([0,11])) }
  var fragmented=SafariDNSWire.TCPReply()
  precondition(tryValue { try fragmented.append(Data([0])) } == nil)
  precondition(tryValue { try fragmented.append(Data([12])+Data(repeating:1,count:11)) } == nil)
  precondition(tryValue { try fragmented.append(Data([2])) }?.count==12)
  var types:[UInt16]=[]
  let v6=SafariPacketRuntime(innerV6:"2001:db8::2") { query,_ in
   let type=UInt16(query[query.count-4])*256+UInt16(query[query.count-3]);types.append(type)
   var reply=query;reply[2]=0x81;reply[3]=0x80
   if type==28 {
    reply[7]=1
    reply.append(contentsOf:[0xc0,12,0,28,0,1,0,0,0,60,0,16])
    reply.append(contentsOf:[0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1])
   }
   return reply
  }
  let addresses=try v6.resolve("v6-only.example")
  precondition(addresses==["2001:db8::1"] && types==[1,28])
  types=[]
  let v4=SafariPacketRuntime(innerV6:"") { query,_ in
   let type=UInt16(query[query.count-4])*256+UInt16(query[query.count-3]);types.append(type)
   var reply=query;reply[2]=0x81;reply[3]=0x80;reply[7]=1
   reply.append(contentsOf:[0xc0,12,0,1,0,1,0,0,0,60,0,4,192,0,2,1]);return reply
  }
  let a=try v4.resolve("v4.example");precondition(a==["192.0.2.1"] && types==[1])
  print("PASS actual SafariDNSWire: max TCP sizes, partial frame rejection, fragmented completion, AAAA-only and IPv4-only resolution")
 }
 static func tryValue<T>(_ body:() throws -> T)->T { do{return try body()}catch{fatalError("unexpected error")}}
}
