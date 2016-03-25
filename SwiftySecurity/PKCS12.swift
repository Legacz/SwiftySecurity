//
//  PKCS12.swift
//  TestSwiftyDocker
//
//  Created by Helge Hess on 07/05/15.
//  Copyright (c) 2015 Helge Hess. All rights reserved.
//

import Foundation

// https://developer.apple.com/library/mac/documentation/Security/Reference/certifkeytrustservices/index.html#//apple_ref/c/func/SecTrustGetTrustResult

public struct PKCS12Item {
  
  let storage : NSDictionary
  
  init(_ storage: NSDictionary) {
    self.storage = storage
  }
  
  public var keyID : NSData? {
    // Typically a SHA-1 digest of the public key
    return storage.secValueForKey(kSecImportItemKeyID)
  }
  public var label : String? {
    return storage.secValueForKey(kSecImportItemLabel)
  }
  
  public var identity : SecIdentity? {
    return storage.secValueForKey(kSecImportItemIdentity)
  }
  public var trust : SecTrust? {
    return storage.secValueForKey(kSecImportItemTrust)
  }
  
  public var certificateChain : [ SecCertificate ]? {
    return storage.secValueForKey(kSecImportItemCertChain)
  }
}

extension PKCS12Item: CustomStringConvertible {
  
  public var description: String {
    var s = "<PKCS12Item:"
    
    if let v = keyID    { s += " id=\(v)" }
    if let v = label    { s += " '\(v)'"  }
    if let v = identity { s += " \(v)"    }
    if let v = trust    { s += " \(v)"    }
    
    if let v = certificateChain {
      s += " certs["
      var isFirst = true
      for cert in v {
        if isFirst { isFirst = false } else { s += ", " }
        s += "\(cert)"
      }
      s += "]"
    }
    
    s += ">"
    return s
  }
}

// PKCS12 is just a wrapper of items
public typealias PKCS12 = [ PKCS12Item ]

public func ImportPKCS12(data: NSData, options: [ String : String ] = [:])
  -> PKCS12?
{
  var keyref : CFArray?
  
  let importStatus = SecPKCS12Import(data, options, &keyref);
  guard importStatus == noErr && keyref != nil else {
    print("PKCS#12 import failed: \(importStatus)")
    return nil
  }
  
  let items = keyref! as NSArray
  return items.map { PKCS12Item($0 as! NSDictionary) }
}

public func ImportPKCS12(path: String, password: String) -> PKCS12? {
  guard let data = NSData(contentsOfFile: path) else { return nil }
  
  let options = [
    String(kSecImportExportPassphrase) : password
  ]
  return ImportPKCS12(data, options: options)
}

extension NSDictionary {

  func secValueForKey<T>(key: CFString) -> T? {
    let key = String(key)
    let v   : AnyObject? = self[key]
    if let vv : AnyObject = v { return (vv as! T)}
    return nil
  }
  
}
