//
//  PEM.swift
//  TestSwiftyDocker
//
//  Created by Helge Hess on 08/05/15.
//  Copyright (c) 2015 Helge Hess. All rights reserved.
//

import Foundation

// Note: Security.framework really wants certificates, not raw keys

public func GetDataFromPEM(s: String, type: String = "CERTIFICATE") -> NSData? {
  // FIXME: lame implementation ;-)
  let keyBegin = "-----BEGIN \(type)-----"
  let keyEnd   = "-----END \(type)-----"
  
  let scanner = NSScanner(string: s)
  scanner.scanUpToString(keyBegin, intoString: nil)
  scanner.scanString    (keyBegin, intoString: nil)
  
  var base64 : NSString?
  scanner.scanUpToString(keyEnd, intoString: &base64)
  if base64 == nil || base64!.length < 1 { return nil }
  
  let opts = NSDataBase64DecodingOptions.IgnoreUnknownCharacters
  return NSData(base64EncodedString: base64! as String, options: opts)
}

public func GetDataFromPEMFile(path: String, type: String = "CERTIFICATE")
         -> NSData?
{
  let s: NSString?
  do {
    s = try NSString(contentsOfFile: path, encoding: NSUTF8StringEncoding)
  } catch _ {
    s = nil
  };
  return s != nil ? GetDataFromPEM(s! as String, type: type) : nil
}
