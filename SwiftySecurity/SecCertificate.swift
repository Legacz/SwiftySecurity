//
//  SecCertificate.swift
//  TestSwiftyDocker
//
//  Created by Helge Hess on 08/05/15.
//  Copyright (c) 2015 Helge Hess. All rights reserved.
//

import Foundation

public extension SecCertificate {
  // TBD: can we do this as initializers?
  
  public static func loadFromDER(data: NSData) -> SecCertificate? {
    return SecCertificateCreateWithData(nil, data).takeRetainedValue()
  }
  
  public static func loadFromDER(path: String) -> SecCertificate? {
    let data = NSData(contentsOfFile: path)
    return data != nil ? loadFromDER(data!) : nil
  }
  
  public var derRepresentation : NSData? {
    let data = SecCertificateCopyData(self)
    return data != nil ? data.takeRetainedValue() as NSData : nil
  }
}

public extension SecCertificate {
  
  public var commonName : String? {
    var value  : Unmanaged<CFString>?
    let status = SecCertificateCopyCommonName(self, &value)
    return value != nil ? value!.takeRetainedValue() as String : nil
  }
  public var subjectSummary : String? {
    let value = SecCertificateCopySubjectSummary(self)
    return value != nil ? value.takeRetainedValue() as String : nil
  }
  
  public var emailAddresses : [ String ]? {
    var value  : Unmanaged<CFArray>?
    let status = SecCertificateCopyEmailAddresses(self, &value)
    if value == nil { return nil }
    
    let array = value!.takeRetainedValue() as! [ String ] // is this really OK?
    return array.isEmpty ? nil : array
  }

  public var publicKey : SecKey? {
    var valueCopy : Unmanaged<SecKey>?
    let status    = SecCertificateCopyPublicKey(self, &valueCopy)
    return valueCopy != nil ? valueCopy!.takeRetainedValue() : nil
  }
  
  public var serialNumber : NSData? {
    // DER-encoded integer (without the tag and length fields)
    var errorRef : Unmanaged<CFError>?
    let value    = SecCertificateCopySerialNumber(self, &errorRef)
    let error    = errorRef?.takeRetainedValue()
    return value != nil ? value.takeRetainedValue() as NSData : nil
  }
}

public extension SecCertificate {

  public var values : [ String : AnyObject ]? {
    return rawValuesForKeys(nil)
  }
  
  public var simpleValues : [ String : AnyObject ]? {
    // FIXME: this can be done better, it's a nested structure
    let rawValues = rawValuesForKeys(nil)
    if rawValues == nil { return nil }
    
    var values = [ String : AnyObject ]()
    for item in rawValues!.values {
      let dict  = item as! NSDictionary
      let label = dict["label"] as? String
      let value : AnyObject? = dict["value"]
      
      if let k = label, v : AnyObject = value {
        values[k] = v
      }
    }
    return values
  }
  
  public func rawValuesForKeys(keys: [ String ]?) -> [ String : AnyObject ]? {
    var errorRef : Unmanaged<CFError>?
    let value    = SecCertificateCopyValues(self, keys, &errorRef)
    let error    = errorRef?.takeRetainedValue()
    if value == nil { return nil }
    return (value.takeRetainedValue() as! [ String : AnyObject ])
  }
}

extension SecCertificate : Printable {
  
  public var description: String {
    // This is not invoked by println, maybe some special handling for CF objs?
    var s = "<SecCertificate:"
    
    if let v = commonName     { s += " cn=\(v)" }
    if let v = subjectSummary { s += " subject=\(v)" }
    
    if let emails = emailAddresses {
      s += " emails["
      var isFirst = true
      for email in emails {
        if isFirst { isFirst = false } else { s += " " }
        s += email
      }
      s += "]"
    }

    s += ">"
    return s
  }
  
}
