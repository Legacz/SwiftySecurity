//
//  SecIdentity.swift
//  TestSwiftyDocker
//
//  Created by Helge Hess on 08/05/15.
//  Copyright (c) 2015 Helge Hess. All rights reserved.
//

import Foundation

public extension SecIdentity {
  // contains a SecKey and an associated SecCertificate
  
  public var certificate : SecCertificate? {
    var valueCopy : SecCertificate?
    SecIdentityCopyCertificate(self, &valueCopy)
    return valueCopy
  }
  
  public var privateKey : SecKey? {
    var valueCopy : SecKey?
    SecIdentityCopyPrivateKey(self, &valueCopy)
    return valueCopy
  }
  
}

public extension SecIdentity {
  
  public static func lookupPreferredIdentity(name:         String,
                                             usageKeys:    [ CFString ]? = nil,
                                             validIssuers: [ NSData   ]? = nil)
                  -> SecIdentity?
  {
    // usageKeys:    kSecAttrCanEncrypt and such
    // validIssuers: subject names of allowed issuers
    let identity = SecIdentityCopyPreferred(name         as CFString,
      usageKeys    as CFArray?,
      validIssuers as CFArray?)
    return identity
  }
  
  public static func systemIdentity(domain: CFString = kSecIdentityDomainDefault)
                  -> ( SecIdentity?, String? )
  {
    // Domains: kSecIdentityDomainDefault, kSecIdentityDomainKerberosKDC
    var identityRef    : SecIdentity?
    var actualDomainCF : CFString?
    
    _ = SecIdentityCopySystemIdentity(domain,
                                      &identityRef, &actualDomainCF)
    let actualDomain : String? = actualDomainCF != nil
      ? (actualDomainCF! as String) : nil
    
    return ( identityRef, actualDomain )
  }
}

extension SecIdentity : CustomStringConvertible {
  
  public var description: String {
    // This is not invoked by println, maybe some special handling for CF objs?
    var s = "<SecIdentity: "
    
    if let v = certificate { s += " cert=\(v)" }
    if let v = privateKey  { s += " key=\(v)" }
    
    s += ">"
    return s
  }
  
}
