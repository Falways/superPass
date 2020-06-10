//
//  main.swift
//  superPass
//
//  Created by 徐航 on 2020/6/9.
//  Copyright © 2020 falways. All rights reserved.


import Foundation
import CryptoSwift

print("super password transform tools with security")
print(["Usage: -h","-encode","-decode"])

/**
Data from bytes:
let data = Data( [0x01, 0x02, 0x03])
 
Data to Array<UInt8>
let bytes = data.bytes                     // [1,2,3]
 
Hexadecimal encoding:
let bytes = Array<UInt8>(hex: "0x010203")  // [1,2,3]
let hex   = bytes.toHexString()            // "010203"
 
Build bytes out of String
let bytes: Array<UInt8> = "cipherkey".bytes  // Array("cipherkey".utf8)
 
Array<UIn8> 转 utf8
String(bytes: decrypted, encoding: .utf8) 
**/

enum Salt {
    static let key = "Super*^=50000000"  // len: 16
    static let iv = "Never)(^-0000005" // len: 16
}

// AES-128 = 16 bytes
// AES-192 = 24 bytes
// AES-256 = 32 bytes
func doEncrypt(_ str:String) -> String {
   do {
        var encryptor = try AES(key: Salt.key, iv: Salt.iv).makeEncryptor()

        var ciphertext = Array<UInt8>()
        // aggregate partial results
        ciphertext += try encryptor.update(withBytes: Array(str.utf8))
        // finish at the end
        ciphertext += try encryptor.finish()
        // 返回16进制string字符串
        return (ciphertext.toHexString())
    } catch {
        print("failure sorry: ")
        print(error)
        return "os not support!"
    }
}

func doDecrypt(_ str:String) -> String {
    do {
        var decryptor = try AES(key: Salt.key, iv: Salt.iv).makeDecryptor()
        var ciphertext = Array<UInt8>()
        ciphertext += try decryptor.update(withBytes: Array<UInt8>(hex: str))
        ciphertext += try decryptor.finish()
        
        return String(bytes: ciphertext, encoding: .utf8) ?? "nil"
    } catch {
        print("failure sorry: ")
        print(error)
        return "os not support!"
    }
}

let args:Array = Swift.CommandLine.arguments

if args.count <= 1 {
    exit(EX_USAGE)
}

print("args[1]: " + args[1])

if args[1] == "-h" {
    print(["Usage: -h","-encode","-decode"])
}else if args[1] == "-encode" {
    print(doEncrypt(args[2]))
}else if args[1] == "-decode" {
    print(doDecrypt(args[2]))
}else {
    print("invalid arguments")
}


//let input: Array<UInt8> = "uuuuu".bytes
//
//print(input)
//
//let key: Array<UInt8> = Salt.key.bytes
//let iv: Array<UInt8> = Salt.iv.bytes
//
//do {
//    let encrypted = try AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7).encrypt(input)
//    let decrypted = try AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7).decrypt(encrypted)
//    print(encrypted)
//    print(String(bytes: decrypted, encoding: .utf8)!)
//} catch {
//    print(error)
//}
