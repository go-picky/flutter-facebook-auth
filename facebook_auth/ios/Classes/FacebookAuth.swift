import FBSDKLoginKit
import Flutter
import AuthenticationServices
import SafariServices
import FBSDKCoreKit
import Foundation
import AuthenticationServices

class FacebookAuth: NSObject {
    let loginManager: LoginManager = .init()
    var pendingResult: FlutterResult? = nil
    private var mainWindow: UIWindow? {
        if let applicationWindow = UIApplication.shared.delegate?.window ?? nil {
            return applicationWindow
        }

        if #available(iOS 13.0, *) {
            if let scene = UIApplication.shared.connectedScenes.first(where: { $0.session.role == .windowApplication }),
               let sceneDelegate = scene.delegate as? UIWindowSceneDelegate,
               let window = sceneDelegate.window as? UIWindow
            {
                return window
            }
        }

        return nil
    }

    /*
     handle the platform channel
     */
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        let args = call.arguments as? [String: Any]

        switch call.method {
        case "login":
            let permissions = args?["permissions"] as! [String]
            let tracking = args?["tracking"] as! String
            let customNonce = args?["nonce"] as? String
            let appId = args?["appId"] as? String

            login(
                permissions: permissions,
                flutterResult: result,
                tracking: tracking == "limited" ? .limited : .enabled,
                appId: appId,
                nonce: customNonce
            )

        case "getAccessToken":

            if let token = AccessToken.current, !token.isExpired {
                let accessToken = getAccessToken(
                    accessToken: token,
                    authenticationToken: AuthenticationToken.current,
                    isLimitedLogin: isLimitedLogin()
                )
                result(accessToken)
            } else if let authToken = AuthenticationToken.current {
                let accessToken = getAccessToken(
                    accessToken: nil,
                    authenticationToken: authToken,
                    isLimitedLogin: isLimitedLogin()
                )
                result(accessToken)
            }else {
                result(nil)
            }

        case "getUserData":
            let fields = args?["fields"] as! String
            getUserData(fields: fields, flutterResult: result)

        case "logOut":
            loginManager.logOut()
            result(nil)

        case "updateAutoLogAppEventsEnabled":
            let enabled = args?["enabled"] as! Bool
            updateAutoLogAppEventsEnabled(enabled: enabled, flutterResult: result)

        case "isAutoLogAppEventsEnabled":
            let enabled: Bool = Settings.shared.isAutoLogAppEventsEnabled
            result(enabled)

        default:
            result(FlutterMethodNotImplemented)
        }
    }

    /*
     use the facebook sdk to request a login with some permissions
     */
    private func login(
        permissions: [String],
        flutterResult: @escaping FlutterResult,
        tracking: LoginTracking,
        appId: String?,
        nonce: String?
    ) {
        if let appId = appId {
            setAppId(appId)
        }

        let isOK = setPendingResult(methodName: "login", flutterResult: flutterResult)
        if !isOK {
            return
        }

        let viewController: UIViewController = (mainWindow?.rootViewController)!

        FacebookSignInHelper.login(permissions: permissions, from: viewController) { result in
            switch result {
            case .success(let data):
                self.setIsLimitedLogin(false) // Assuming non-limited login
                self.finishWithResult(
                    data: self.getAccessToken(
                        accessToken: AccessToken(tokenString: data.accessToken, permissions: data.grantedPermissions, declinedPermissions: [], expiredPermissions: [], appID: Settings.shared.appID ?? "", userID: "", expirationDate: Date().addingTimeInterval(3600), refreshDate: Date(), dataAccessExpirationDate: nil),
                        authenticationToken: nil, // You might need to adjust this
                        isLimitedLogin: false
                            )
                        )
            case .failure(let error):
                self.finishWithError(errorCode: "FAILED", message: error.localizedDescription)
            }
        }
        if appId != nil {
            resetApplicationId()
        }
    }

    /**
     retrive the user data from facebook, this could be fail if you are trying to get data without the user autorization permission
     */
    private func getUserData(fields: String, flutterResult: @escaping FlutterResult) {
        let graphRequest = GraphRequest(graphPath: "me", parameters: ["fields": fields])
        graphRequest.start { _, result, error in
            if error != nil {
                self.sendErrorToClient(result: flutterResult, errorCode: "FAILED", message: error!.localizedDescription)
            } else {
                let resultDic = result as! NSDictionary
                flutterResult(resultDic) // send the response to the client
            }
        }
    }

    /**
     Enable or disable the AutoLogAppEvents
     */
    private func updateAutoLogAppEventsEnabled(enabled: Bool, flutterResult: @escaping FlutterResult) {
        Settings.shared.isAutoLogAppEventsEnabled = enabled
        flutterResult(nil)
    }

    // define a login task
    private func setPendingResult(methodName: String, flutterResult: @escaping FlutterResult) -> Bool {
        if pendingResult != nil { // if we have a previous login task
            sendErrorToClient(result: pendingResult!, errorCode: "OPERATION_IN_PROGRESS", message: "The method \(methodName) called while another Facebook login operation was in progress.")
            return false
        }
        pendingResult = flutterResult
        return true
    }

    // send the success response to the client
    private func finishWithResult(data: Any?) {
        if pendingResult != nil {
            pendingResult!(data)
            pendingResult = nil
        }
    }

    // handle the login errors
    private func finishWithError(errorCode: String, message: String) {
        if pendingResult != nil {
            sendErrorToClient(result: pendingResult!, errorCode: errorCode, message: message)
            pendingResult = nil
        }
    }

    // sends a error response to the client
    private func sendErrorToClient(result: FlutterResult, errorCode: String, message: String) {
        result(FlutterError(code: errorCode, message: message, details: nil))
    }

    /**
     get the access token data as a Dictionary
     */
    private func getAccessToken(
        accessToken: AccessToken?,
        authenticationToken: AuthenticationToken?,
        isLimitedLogin: Bool
    ) -> [String: Any] {
        if isLimitedLogin || accessToken == nil {
            return [
                "type": "limited",
                "userId": Profile.current?.userID,
                "userEmail": Profile.current?.email,
                "userName": Profile.current?.name,
                "token": authenticationToken?.tokenString,
                "nonce": authenticationToken?.nonce,
            ]
        }

        return [
            "type": "classic",
            "token": accessToken!.tokenString,
            "userId": accessToken!.userID,
            "expires": Int64((accessToken!.expirationDate.timeIntervalSince1970 * 1000).rounded()),
            "applicationId": accessToken!.appID,
            "grantedPermissions": accessToken!.permissions.map { $0.name },
            "declinedPermissions": accessToken!.declinedPermissions.map { $0.name },
            "authenticationToken": authenticationToken?.tokenString,
        ]
    }

    private func setIsLimitedLogin(_ value: Bool) {
        UserDefaults.standard.set(value, forKey: "facebook_limited_login")
    }

    private func isLimitedLogin() -> Bool {
        return UserDefaults.standard.bool(forKey: "facebook_limited_login")
    }

    private func setAppId(_ appId: String) {
        print("Setting App ID to: \(appId)")
        Settings.shared.appID = appId
        print("App ID after setting: \(Settings.shared.appID ?? "nil")")
    }

    private func resetApplicationId() {
        print("Resetting Application ID")
        if let bundleId = Bundle.main.bundleIdentifier,
        let appId = Bundle.main.object(forInfoDictionaryKey: "FacebookAppID") as? String {
            if appId.lowercased().hasPrefix("fb") {
                Settings.shared.appID = String(appId.dropFirst(2))
            } else {
                Settings.shared.appID = appId
            }
        }
        print("App ID after reset: \(Settings.shared.appID ?? "nil")")
    }
}

public class FacebookSignInHelper: NSObject, ASWebAuthenticationPresentationContextProviding {
    private static var shared: FacebookSignInHelper?
    private let appID: String
    private let redirectURI: String
    private var completionHandler: ((Result<(accessToken: String, grantedPermissions: [String]), Error>) -> Void)?
    private var permissions: [String]

    public static func login(
        permissions: [String] = ["public_profile", "email"],
        from viewController: UIViewController,
        completion: @escaping (Result<(accessToken: String, grantedPermissions: [String]), Error>) -> Void
    ) {
        guard shared == nil else {
            completion(.failure(NSError(domain: "FacebookLogin", code: -1, userInfo: [NSLocalizedDescriptionKey: "Already logging in"])))
            return
        }

        let appID = Settings.shared.appID ?? ""
        let redirectURI = "fb\(appID)"
        shared = FacebookSignInHelper(appID: appID, redirectURI: redirectURI, permissions: permissions)
        shared?.login(from: viewController) { result in
            shared = nil
            completion(result)
        }
    }

    private init(appID: String, redirectURI: String, permissions: [String]) {
        self.appID = appID
        self.redirectURI = redirectURI
        self.permissions = permissions
        super.init()
    }

    private func login(from viewController: UIViewController, completion: @escaping (Result<(accessToken: String, grantedPermissions: [String]), Error>) -> Void) {
        self.completionHandler = completion
        guard let authURL = constructFacebookAuthURL() else {
            completion(.failure(NSError(domain: "FacebookLogin", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to construct Facebook auth URL"])))
            return
        }
        let session = ASWebAuthenticationSession(url: authURL, callbackURLScheme: redirectURI) { callbackURL, error in
            self.handleAuthResult(callbackURL: callbackURL, error: error)
        }
        session.presentationContextProvider = self
        session.start()
    }

    private func constructFacebookAuthURL() -> URL? {
        guard var components = URLComponents(string: "https://www.facebook.com/v21.0/dialog/oauth") else {
            return nil
        }
        components.queryItems = [
            URLQueryItem(name: "client_id", value: appID),
            URLQueryItem(name: "display", value: "touch"),
            URLQueryItem(name: "return_scopes", value: "true"),
            URLQueryItem(name: "redirect_uri", value: "\(redirectURI)://authorize"),
            URLQueryItem(name: "response_type", value: "token"),
            URLQueryItem(name: "scope", value: permissions.joined(separator: ",")),
            URLQueryItem(name: "auth_type", value: "rerequest")
        ]
        return components.url
    }

    private func handleAuthResult(callbackURL: URL?, error: Error?) {
        if let error = error {
            completionHandler?(.failure(error))
            return
        }

        guard let callbackURL = callbackURL,
              let fragment = callbackURL.fragment else {
            completionHandler?(.failure(NSError(domain: "FacebookLogin", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid callback URL"])))
            return
        }

        let params = fragment.components(separatedBy: "&")
            .map { $0.components(separatedBy: "=") }
            .reduce(into: [String: String]()) { result, param in
                if param.count == 2 {
                    result[param[0]] = param[1].removingPercentEncoding
                }
            }
        if let accessToken = params["access_token"], let grantedScopes = params["granted_scopes"]?.split(separator: ",").map(String.init) {
            completionHandler?(.success((accessToken: accessToken, grantedPermissions: grantedScopes)))
        } else if let error = params["error"] {
            completionHandler?(.failure(NSError(domain: "FacebookLogin", code: -1, userInfo: [NSLocalizedDescriptionKey: error])))
        } else {
            completionHandler?(.failure(NSError(domain: "FacebookLogin", code: -1, userInfo: [NSLocalizedDescriptionKey: "Unknown error occurred"])))
        }
    }

    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.windows[0]
    }
}

