//
//  Authentication.swift
//  StosSign
//
//  Created by Stossy11 on 18/12/2025.
//

import Foundation
import StosSign_API
import StosSign_Common
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public typealias AppleAPISession = StosSign_API.AppleAPISession
public typealias AppleAPIError = StosSign_API.AppleAPIError

public enum TwoFactorMethod: String, Sendable {
    case trustedDevice
    case sms
    case voice
}

public final class Authentication {
    public init() { }
    
    public static let dateFormatter = ISO8601DateFormatter()
    
    public static func authenticate(
        appleID unsanitizedAppleID: String,
        password: String,
        anisetteData: AnisetteData,
        smsClientInfo: String? = nil,
        methodSelectionHandler: (([TwoFactorMethod]) async -> TwoFactorMethod?)? = nil,
        verificationHandler: ((@escaping (String?) -> Void) async -> Void)? = nil
    ) async throws -> (Account, AppleAPISession) {
        let sanitizedAppleID = unsanitizedAppleID.lowercased()
        let macOSClientInfo: AnisetteData = .init(machineID: anisetteData.machineID, oneTimePassword: anisetteData.oneTimePassword, localUserID: anisetteData.localUserID, routingInfo: anisetteData.routingInfo, deviceUniqueIdentifier: anisetteData.deviceUniqueIdentifier, deviceSerialNumber: anisetteData.deviceSerialNumber, deviceDescription: smsClientInfo ?? anisetteData.deviceDescription, date: anisetteData.date, locale: anisetteData.locale, timeZone: anisetteData.timeZone)
        
        print(anisetteData.deviceDescription)
        print(macOSClientInfo.deviceDescription)
        
        let clientDictionary: [String: Any] = [
            "bootstrap": true,
            "icscrec": true,
            "pbe": false,
            "prkgen": true,
            "svct": "iCloud",
            "loc": Locale.current.identifier,
            "X-Apple-Locale": Locale.current.identifier,
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-M": anisetteData.machineID,
            "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
            "X-Apple-I-MD-LU": anisetteData.localUserID,
            "X-Apple-I-MD-RINFO": anisetteData.routingInfo,
            "X-Apple-I-SRL-NO": anisetteData.deviceSerialNumber,
            "X-Apple-I-Client-Time": dateFormatter.string(from: anisetteData.date),
            "X-Apple-I-TimeZone": TimeZone.current.abbreviation() ?? "PST"
        ]
        
        let context = GSAContext(username: sanitizedAppleID, password: password)
        guard let publicKey = context.start() else {
            throw AppleAPIError.authenticationHandshakeFailed
        }
        
        let initialParameters: [String: Any] = [
            "A2k": publicKey,
            "cpd": clientDictionary,
            "ps": ["s2k", "s2k_fo"],
            "o": "init",
            "u": sanitizedAppleID
        ]
        
        let responseDictionary = try await sendAuthenticationRequest(
            parameters: initialParameters,
            anisetteData: anisetteData
        )
        
        guard let c = responseDictionary["c"] as? String,
              let salt = responseDictionary["s"] as? Data,
              let iterations = responseDictionary["i"] as? Int,
              let serverPublicKey = responseDictionary["B"] as? Data
        else {
            throw URLError(.badServerResponse)
        }
        
        context.salt = salt
        context.serverPublicKey = serverPublicKey
        
        let sp = responseDictionary["sp"] as? String
        let isHexadecimal = (sp == "s2k_fo")
        
        guard let verificationMessage = context.makeVerificationMessage(
            iterations: iterations,
            isHexadecimal: isHexadecimal
        ) else {
            throw AppleAPIError.authenticationHandshakeFailed
        }
        
        let verificationParameters: [String: Any] = [
            "c": c,
            "cpd": clientDictionary,
            "M1": verificationMessage,
            "o": "complete",
            "u": sanitizedAppleID
        ]
        
        let verificationResponse = try await sendAuthenticationRequest(
            parameters: verificationParameters,
            anisetteData: anisetteData
        )
        
        guard let serverVerificationMessage = verificationResponse["M2"] as? Data,
              let serverDictionary = verificationResponse["spd"] as? Data,
              let statusDictionary = verificationResponse["Status"] as? [String: Any]
        else {
            throw URLError(.badServerResponse)
        }
        
        guard context.verifyServerVerificationMessage(serverVerificationMessage) else {
            throw AppleAPIError.authenticationHandshakeFailed
        }
        
        guard let decryptedData = serverDictionary.decryptedCBC(context: context) else {
            throw AppleAPIError.authenticationHandshakeFailed
        }
        
        guard let decryptedDictionary = try PropertyListSerialization.propertyList(
            from: decryptedData,
            format: nil
        ) as? [String: Any],
              let dsid = decryptedDictionary["adsid"] as? String,
              let idmsToken = decryptedDictionary["GsIdmsToken"] as? String
        else {
            throw URLError(.badServerResponse)
        }
        
        context.dsid = dsid
        
        let authType = statusDictionary["au"] as? String
        switch authType {
        case "trustedDeviceSecondaryAuth", "trustedDevice", "pushedCode":
            guard let verificationHandler = verificationHandler else {
                throw AppleAPIError.requiresTwoFactorAuthentication
            }
            
            let method = await methodSelectionHandler?([.trustedDevice, .sms, .voice]) ?? .trustedDevice
            switch method {
            case .trustedDevice:
                try await requestTrustedDeviceTwoFactorCode(dsid: dsid, idmsToken: idmsToken, anisetteData: macOSClientInfo, verificationHandler: verificationHandler)
            case .sms, .voice:
                try await requestSMSTwoFactorCode(dsid: dsid, idmsToken: idmsToken, anisetteData: macOSClientInfo, mode: method == .voice ? "voice" : "sms", phoneID: trustedPhoneID(from: statusDictionary) ?? "1", verificationHandler: verificationHandler)
            }
            
            return try await authenticate(
                appleID: unsanitizedAppleID,
                password: password,
                anisetteData: anisetteData,
                smsClientInfo: smsClientInfo,
                methodSelectionHandler: methodSelectionHandler,
                verificationHandler: verificationHandler
            )
            
        case "secondaryAuth", "sms", "voice", "phone":
            guard let verificationHandler = verificationHandler else {
                throw AppleAPIError.requiresTwoFactorAuthentication
            }
            
            let method = await methodSelectionHandler?([.trustedDevice, .sms, .voice]) ?? .sms
            switch method {
            case .trustedDevice:
                try await requestTrustedDeviceTwoFactorCode(dsid: dsid, idmsToken: idmsToken, anisetteData: macOSClientInfo, verificationHandler: verificationHandler)
            case .sms, .voice:
                try await requestSMSTwoFactorCode(dsid: dsid, idmsToken: idmsToken, anisetteData: macOSClientInfo, mode: method == .voice ? "voice" : "sms", phoneID: trustedPhoneID(from: statusDictionary) ?? "1", verificationHandler: verificationHandler)
            }
            
            return try await authenticate(
                appleID: unsanitizedAppleID,
                password: password,
                anisetteData: anisetteData,
                smsClientInfo: smsClientInfo,
                methodSelectionHandler: methodSelectionHandler,
                verificationHandler: verificationHandler
            )
            
        default:
            guard let sessionKey = decryptedDictionary["sk"] as? Data,
                  let c = decryptedDictionary["c"] as? Data
            else {
                throw URLError(.badServerResponse)
            }
            
            context.sessionKey = sessionKey
            
            let app = "com.apple.gs.xcode.auth"
            guard let checksum = context.makeChecksum(appName: app) else {
                throw AppleAPIError.authenticationHandshakeFailed
            }
            
            let tokenParameters: [String: Any] = [
                "app": [app],
                "c": c,
                "checksum": checksum,
                "cpd": clientDictionary,
                "o": "apptokens",
                "t": idmsToken,
                "u": dsid
            ]
            
            
            let token = try await fetchAuthToken(
                app: app,
                parameters: tokenParameters,
                context: context,
                anisetteData: anisetteData
            )
            
            let session = AppleAPISession(
                dsid: dsid,
                authToken: token,
                anisetteData: anisetteData
            )
            
            let account = try await AppleAPI.shared.fetchAccount(session: session)
            return (account, session)
        }
    }
    
    public static func authenticate(
        appleID unsanitizedAppleID: String,
        password: String,
        anisetteData: AnisetteData,
        smsClientInfo: String? = nil,
        methodSelectionHandler: (([TwoFactorMethod]) async -> TwoFactorMethod?)? = nil,
        verificationHandler: ((@escaping (String?) -> Void) -> Void)? = nil,
        completionHandler: @escaping (Account?, AppleAPISession?, Error?) -> Void
    ) {
        Task {
            do {
                let success = try await authenticate(appleID: unsanitizedAppleID, password: password, anisetteData: anisetteData, smsClientInfo: smsClientInfo, methodSelectionHandler: methodSelectionHandler) { veri in
                    verificationHandler?(veri)
                }
                
                completionHandler(success.0, success.1, nil)
            } catch {
                completionHandler(nil, nil, error)
            }
        }
    }
    

    public static func sendAuthenticationRequest(
        parameters requestParameters: [String: Any],
        anisetteData: AnisetteData
    ) async throws -> [String: Any] {
        guard let requestURL = URL(string: "https://gsa.apple.com/grandslam/GsService2") else {
            throw AppleAPIError.unknown
        }
        
        let parameters: [String: Any] = [
            "Header": ["Version": "1.0.1"],
            "Request": requestParameters
        ]
        
        var httpHeaders = [
            "Content-Type": "text/x-xml-plist",
            "X-MMe-Client-Info": anisetteData.deviceDescription,
            // GrandSlam negotiates the response format from Accept. Using */*
            // can make Apple return JSON, which then causes Cocoa error 3840
            // when the response is decoded as an XML plist.
            "Accept": "text/x-xml-plist",
            // Apple currently rejects the macOS GrandSlam identity with -80045.
            // Match iLoader 2.3.7 and use the Android AuthKit identity.
            "User-Agent": "akd/1.0 CFNetwork/808.1.4",
            "X-Xcode-Version": "26.0 (26A242)",
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "Connection": "close"
        ]
        
        let bodyData = try PropertyListSerialization.data(
            fromPropertyList: parameters,
            format: .xml,
            options: 0
        )
        
        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.httpBody = bodyData
        httpHeaders.forEach { request.addValue($0.value, forHTTPHeaderField: $0.key) }
        
        let (data, _) = try await AppleAPI.shared.session.data(for: request)
        
        let responseDictionary: [String: Any]
        do {
            guard let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
                throw URLError(.badServerResponse)
            }
            responseDictionary = plist
        } catch {
            // Preserve the real server payload instead of exposing the opaque
            // NSCocoaErrorDomain 3840 parsing error to the user.
            let preview = String(data: data.prefix(512), encoding: .utf8) ?? "<binary response>"
            throw AppleAPIError.customError(code: 3840, message: "Apple returned an invalid GrandSlam response: \(preview)")
        }

        guard let dictionary = responseDictionary["Response"] as? [String: Any],
              let status = dictionary["Status"] as? [String: Any] else {
            throw AppleAPIError.badServerResponse
        }
        
        let errorCode = status["ec"] as? Int ?? 0
        guard errorCode == 0 else {
            switch errorCode {
            case -20101, -22406:
                throw AppleAPIError.incorrectCredentials
            case -22421:
                throw AppleAPIError.invalidAnisetteData
            case -20209:
                throw AppleAPIError.accountLocked
            default:
                guard let errorDescription = status["em"] as? String else {
                    throw AppleAPIError.unknown
                }
                
                let localizedDescription = "\(errorDescription) (\(errorCode))"
                throw AppleAPIError.customError(code: errorCode, message: localizedDescription)
            }
        }
        
        return dictionary
    }

    public static func makeTwoFactorCodeRequest(
        url: URL,
        dsid: String,
        idmsToken: String,
        anisetteData: AnisetteData
    ) -> URLRequest {
        let identityToken = "\(dsid):\(idmsToken)"
        let encodedIdentityToken = identityToken.data(using: .utf8)?.base64EncodedString() ?? ""
        
        let httpHeaders = [
            "Accept": "application/x-buddyml",
            "Accept-Language": "en-us",
            "Content-Type": "application/x-plist",
            "User-Agent": "Xcode",
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "26.0 (26A242)",
            "X-Apple-Identity-Token": encodedIdentityToken,
            "X-Apple-I-MD-M": anisetteData.machineID,
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-LU": anisetteData.localUserID,
            "X-Apple-I-MD-RINFO": "\(anisetteData.routingInfo)",
            "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
            "X-MMe-Client-Info": anisetteData.deviceDescription,
            "X-Apple-I-Client-Time": dateFormatter.string(from: anisetteData.date),
            "X-Apple-Locale": anisetteData.locale.identifier,
            "X-Apple-I-TimeZone": anisetteData.timeZone.abbreviation() ?? "PST",
            "Connection": "close"
        ]
        
        var request = URLRequest(url: url)
        httpHeaders.forEach { request.addValue($0.value, forHTTPHeaderField: $0.key) }
        
        return request
    }
    
    
    // Private funcs :3

    public static func fetchAuthToken(
        app: String,
        parameters: [String: Any],
        context: GSAContext,
        anisetteData: AnisetteData
    ) async throws -> String {
        let responseDictionary = try await sendAuthenticationRequest(
            parameters: parameters,
            anisetteData: anisetteData
        )
        
        guard let encryptedToken = responseDictionary["et"] as? Data else {
            throw URLError(.badServerResponse)
        }
        
        guard let token = encryptedToken.decryptedGCM(context: context) else {
            throw AppleAPIError.authenticationHandshakeFailed
        }
        
        guard let tokensDictionary = try PropertyListSerialization.propertyList(
            from: token,
            format: nil
        ) as? [String: Any] else {
            throw URLError(.badServerResponse)
        }
        
        guard let appTokens = tokensDictionary["t"] as? [String: Any],
              let tokens = appTokens[app] as? [String: Any],
              let authToken = tokens["token"] as? String
        else {
            throw URLError(.badServerResponse)
        }
        
        return authToken
    }

    private static func trustedPhoneID(from status: [String: Any]?) -> String? {
        guard let status else { return nil }
        if let phone = status["phoneNumber"] as? [String: Any],
           let id = phone["id"] as? CustomStringConvertible {
            return id.description
        }
        for key in ["trustedPhoneNumbers", "phoneNumbers"] {
            if let phones = status[key] as? [[String: Any]],
               let id = phones.first?["id"] as? CustomStringConvertible {
                return id.description
            }
        }
        return nil
    }

    public static func requestTrustedDeviceTwoFactorCode(
        dsid: String,
        idmsToken: String,
        anisetteData: AnisetteData,
        verificationHandler: @escaping (@escaping (String?) -> Void) async -> Void
    ) async throws {
        let requestURL = URL(string: "https://gsa.apple.com/auth/verify/trusteddevice")!
        var request = makeTwoFactorCodeRequest(url: requestURL, dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData)
        request.httpMethod = "GET"
        let (data, response) = try await AppleAPI.shared.session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw AppleAPIError.customError(code: (response as? HTTPURLResponse)?.statusCode ?? 0, message: "Apple rejected trusted-device verification: \(body)")
        }

        let code = try await withCheckedThrowingContinuation { continuation in
            Task { await verificationHandler { continuation.resume(returning: $0) } }
        }
        guard let code else { throw AppleAPIError.requiresTwoFactorAuthentication }

        var verifyRequest = makeTwoFactorCodeRequest(url: URL(string: "https://gsa.apple.com/grandslam/GsService2/validate")!, dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData)
        verifyRequest.setValue(code, forHTTPHeaderField: "security-code")
        let (verifyData, verifyResponse) = try await AppleAPI.shared.session.data(for: verifyRequest)
        try validateTwoFactorResponse(data: verifyData, response: verifyResponse, requirePhoneToken: false)
    }

    public static func requestSMSTwoFactorCode(
        dsid: String,
        idmsToken: String,
        anisetteData: AnisetteData,
        mode: String = "sms",
        phoneID: String = "1",
        verificationHandler: @escaping (@escaping (String?) -> Void) async -> Void
    ) async throws {
        let requestURL = URL(string: "https://gsa.apple.com/auth/verify/phone/put?mode=\(mode)")!
        var request = makeTwoFactorCodeRequest(url: requestURL, dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData)
        request.httpMethod = "POST"
        request.httpBody = try PropertyListSerialization.data(fromPropertyList: [
            "serverInfo": ["mode": mode, "phoneNumber.id": phoneID]
        ], format: .xml, options: 0)
        let (data, response) = try await AppleAPI.shared.session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw AppleAPIError.customError(code: (response as? HTTPURLResponse)?.statusCode ?? 0, message: "Apple rejected \(mode) verification for phone ID \(phoneID): \(body)")
        }

        let code = try await withCheckedThrowingContinuation { continuation in
            Task { await verificationHandler { continuation.resume(returning: $0) } }
        }
        guard let code else { throw AppleAPIError.requiresTwoFactorAuthentication }

        var verifyRequest = makeTwoFactorCodeRequest(url: URL(string: "https://gsa.apple.com/auth/verify/phone/securitycode?referrer=/auth/verify/phone/put")!, dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData)
        verifyRequest.httpMethod = "POST"
        verifyRequest.httpBody = try PropertyListSerialization.data(fromPropertyList: [
            "securityCode.code": code,
            "serverInfo": ["mode": mode, "phoneNumber.id": phoneID]
        ], format: .xml, options: 0)
        let (verifyData, verifyResponse) = try await AppleAPI.shared.session.data(for: verifyRequest)
        try validateTwoFactorResponse(data: verifyData, response: verifyResponse, requirePhoneToken: true)
    }

    private static func validateTwoFactorResponse(data: Data, response: URLResponse, requirePhoneToken: Bool) throws {
        let dict = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
            ?? ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any])
        let status = response as? HTTPURLResponse
        let errorCode = dict?["ec"] as? Int ?? 0
        let message = dict?["em"] as? String ?? String(data: data, encoding: .utf8) ?? "Apple returned an invalid verification response"
        if errorCode == -21669 { throw AppleAPIError.incorrectVerificationCode }
        if errorCode != 0 { throw AppleAPIError.customError(code: errorCode, message: message) }
        guard status?.statusCode == 200 else { throw AppleAPIError.customError(code: status?.statusCode ?? 0, message: message) }
        if requirePhoneToken {
            let hasToken = status?.allHeaderFields.keys.contains { ($0 as? String)?.lowercased() == "x-apple-pe-token" } == true
            guard hasToken else { throw AppleAPIError.incorrectVerificationCode }
        }
    }

}
