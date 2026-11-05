import Foundation
import Darwin
final class SafariPacketRuntime {
 let innerV6: String
 let handler: (Data, Bool) throws -> Data
 init(innerV6: String, handler: @escaping (Data,Bool) throws -> Data) { self.innerV6=innerV6; self.handler=handler }
 func dns(_ query: Data, tcp: Bool) throws -> Data { try handler(query,tcp) }
}
enum SafariNetstack {
 static func numericIP(_ ip: String) -> Bool { var a=in_addr();var b=in6_addr();return ip.withCString { inet_pton(AF_INET,$0,&a)==1 || inet_pton(AF_INET6,$0,&b)==1 } }
}
