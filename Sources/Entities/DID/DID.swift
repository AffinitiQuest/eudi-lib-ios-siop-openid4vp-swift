/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import Foundation
import SwiftyJSON
import JOSESwift

public let DID_URL_SYNTAX = try? NSRegularExpression(pattern: "^did:[a-z0-9]+:(([A-Z.a-z0-9]|-|_|%[0-9A-Fa-f][0-9A-Fa-f])*:)*([A-Z.a-z0-9]|-|_|%[0-9A-Fa-f][0-9A-Fa-f])+(/(([-A-Z._a-z0-9]|~)|%[0-9A-Fa-f][0-9A-Fa-f]|([!$&'()*+,;=])|:|@)*)*(\\?(((([-A-Z._a-z0-9]|~)|%[0-9A-Fa-f][0-9A-Fa-f]|([!$&'()*+,;=])|:|@)|/|\\?)*))?(#(((([-A-Z._a-z0-9]|~)|%[0-9A-Fa-f][0-9A-Fa-f]|([!$&'()*+,;=])|:|@)|/|\\?)*))?$", options: [])
public let DID_SYNTAX = try? NSRegularExpression(pattern: "^did:[a-z0-9]+:(([A-Z.a-z0-9]|-|_|%[0-9A-Fa-f][0-9A-Fa-f])*:)*([A-Z.a-z0-9]|-|_|%[0-9A-Fa-f][0-9A-Fa-f])+$", options: [])

public struct AbsoluteDIDUrl {
  private let uri: URL
  
  private init(uri: URL) {
    self.uri = uri
  }
  
  var string: String {
    return uri.absoluteString
  }
  
  public static func parse(_ string: String) -> AbsoluteDIDUrl? {
    guard let regex = DID_URL_SYNTAX else {
      return nil
    }
    
    let parsed = DID.parse(string, regex: regex)
    if regex.matches(
      in: string,
      options: [],
      range: NSRange(
        location: 0, length: string.utf16.count
      )
    ).isEmpty == false && parsed != nil {
      if let url = URL(string: string) {
        return AbsoluteDIDUrl(uri: url)
      } else {
        return nil
      }
    } else {
      return nil
    }
  }
}

public struct DID {
  
  public let uri: URL
  
  public init(uri: URL) {
    self.uri = uri
  }
  
  public var string: String {
    return uri.absoluteString
  }
  
  public static func parse(_ string: String, regex: NSRegularExpression? = DID_SYNTAX) -> DID? {
    guard
      let regex = regex,
      regex.matches(
        in: string,
        options: [],
        range: NSRange(
          location: 0,
          length: string.utf16.count
        )
      ).isEmpty == false,
      let url = URL(string: string)
    else {
      return nil
    }
    
    return DID(uri: url)
  }
}

public class AQDidResolver: DIDPublicKeyLookupAgentType {
    public init() {}
    
    public func resolveDidDocument(didUrl: String) async -> JSON? {
        let temp = didUrl.split(separator: OpenId4VPSpec.clientIdSchemeSeparator, maxSplits: 2)
        var urlString = "https://\(temp.dropFirst(2).joined(separator: "/"))"
        guard let url = URL(string: urlString) else { return nil }
        if didUrl.last! == ":" {
            urlString.append("did.json")
        } else if url.pathComponents.count <= 1 {
            urlString.append("/.well-known/did.json")
        } else {
            urlString.append("/did.json")
        }
        
        guard let didUrl = URL(string: urlString) else { return nil }
        let didDocumentJson: JSON?
        
        do {
            let (didDocumentData, response) = try await URLSession.shared.data(from: didUrl)
            guard let didDocumentJSON = try? JSON(data: didDocumentData) else { return nil }
            didDocumentJson = didDocumentJSON
        } catch { return nil }
        
        guard let didDocumentJson else { return nil }
        return didDocumentJson
    }
    
    public func resolveKey(from didUrl: DID) async -> SecKey? {
        let didUri = didUrl.string
        let parts = didUri.components(separatedBy: "%23")
        guard parts.count == 2 else { return nil }
        let (didUrl, kid) = (parts[0], parts[1])
        guard let didJson = await resolveDidDocument(didUrl: didUrl) else { return nil }
        let verificationMethods = didJson["verificationMethod"].arrayValue
        var key: SecKey?
        for verificationMethod in verificationMethods {
            if verificationMethod["id"].stringValue == "#\(kid)" {
                do {
                    var error: Unmanaged<CFError>?
                    let keyDictionary = verificationMethod["publicKeyJwk"]
                    let keyData = NSMutableData.init(bytes: [0x04], length: [0x04].count)
                    var xString = keyDictionary["x"].stringValue
                    var yString = keyDictionary["y"].stringValue
                    
                    xString = xString.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
                    if xString.count % 4 == 2 {
                        xString.append("==")
                    }
                    if xString.count % 4 == 3 {
                        xString.append("=")
                    }
                    
                    yString = yString.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
                    if yString.count % 4 == 2 {
                        yString.append("==")
                    }
                    if yString.count % 4 == 3 {
                        yString.append("=")
                    }
                    
                    let xBytes = Data(base64Encoded: xString)
                    /*Same with y and d*/
                    let yBytes = Data(base64Encoded: yString)
                    
                    keyData.append(xBytes!)
                    keyData.append(yBytes!)
                    let attributes: [String: Any] = [
                        kSecAttrKeyType as String: kSecAttrKeyTypeEC,
                        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                        kSecAttrKeySizeInBits as String: 256,
                        kSecAttrIsPermanent as String: false
                    ]
                    key = try SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error)
                    print(error)
                } catch let error {
                    print(error)
                }
            }
        }
        guard let key else { return nil }
        return key
    }
}


