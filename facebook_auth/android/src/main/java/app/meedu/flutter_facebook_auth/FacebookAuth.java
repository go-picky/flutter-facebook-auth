package app.meedu.flutter_facebook_auth;

import static com.facebook.FacebookSdk.APPLICATION_ID_PROPERTY;

import android.app.Activity;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import com.facebook.*;
import com.facebook.login.LoginBehavior;
import com.facebook.login.LoginManager;
import io.flutter.plugin.common.MethodChannel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import org.json.JSONObject;

public class FacebookAuth {
  private final LoginManager loginManager;
  FacebookLoginResultDelegate resultDelegate;

  FacebookAuth() {
    loginManager = LoginManager.getInstance();
    CallbackManager callbackManager = CallbackManager.Factory.create();
    resultDelegate = new FacebookLoginResultDelegate(callbackManager);
    loginManager.registerCallback(callbackManager, resultDelegate);
  }

  /**
   * @param accessToken an instance of Facebook SDK AccessToken
   * @return a HashMap data
   */
  static HashMap<String, Object> getAccessToken(final AccessToken accessToken) {
    return new HashMap<String, Object>() {
      {
        put("token", accessToken.getToken());
        put("userId", accessToken.getUserId());
        put("expires", accessToken.getExpires().getTime());
        put("applicationId", accessToken.getApplicationId());
        put("lastRefresh", accessToken.getLastRefresh().getTime());
        put("isExpired", accessToken.isExpired());
        put("grantedPermissions", new ArrayList<>(accessToken.getPermissions()));
        put("declinedPermissions", new ArrayList<>(accessToken.getDeclinedPermissions()));
        put("dataAccessExpirationTime", accessToken.getDataAccessExpirationTime().getTime());
      }
    };
  }

  /**
   * Logs in the user with the specified permissions.
   *
   * @param activity the current activity
   * @param appId the Facebook application ID
   * @param permissions the list of permissions to request
   * @param result the result callback for the login operation
   */
  void login(
      Activity activity,
      String appId,
      List<String> permissions,
      MethodChannel.Result result) {
    final boolean hasPreviousSession = AccessToken.getCurrentAccessToken() != null;
    if (hasPreviousSession) {
      loginManager.logOut();
    }
    final boolean isOk = resultDelegate.setPendingResult(result);
    if (isOk) {
      try {
        if (appId != null) {
          FacebookSdk.setApplicationId(appId);
        }
        loginManager.logIn(activity, permissions);
      } finally {
        if (appId != null) {
          this.resetApplicationId();
        }
      }
    }
  }

  /**
   * set the login behavior to use native app, webview, dialogs, etc
   *
   * @param behavior string that defines the ui type for login
   */
  public void setLoginBehavior(String behavior) {
    LoginBehavior loginBehavior;
    switch (behavior) {
      case "NATIVE_ONLY":
        loginBehavior = LoginBehavior.NATIVE_ONLY;
        break;
      case "KATANA_ONLY":
        loginBehavior = LoginBehavior.KATANA_ONLY;
        break;
      case "DIALOG_ONLY":
        loginBehavior = LoginBehavior.DIALOG_ONLY;
        break;
      case "DEVICE_AUTH":
        loginBehavior = LoginBehavior.DEVICE_AUTH;
        break;
      case "WEB_ONLY":
        loginBehavior = LoginBehavior.WEB_ONLY;
        break;

      default:
        loginBehavior = LoginBehavior.NATIVE_WITH_FALLBACK;
    }

    loginManager.setLoginBehavior(loginBehavior);
  }

  /**
   * Gets current access token, if one exists
   *
   * @param result flutter method channel result to send the response to the client
   */
  public void getAccessToken(MethodChannel.Result result) {
    AccessToken accessToken = AccessToken.getCurrentAccessToken();
    boolean isLoggedIn = accessToken != null && !accessToken.isExpired();
    if (isLoggedIn) {
      HashMap<String, Object> data = getAccessToken(AccessToken.getCurrentAccessToken());
      result.success(data);
    } else {
      result.success(null);
    }
  }

  /**
   * close the current facebook session
   *
   * @param result flutter method channel result to send the response to the client
   */
  void logOut(MethodChannel.Result result) {
    final boolean hasPreviousSession = AccessToken.getCurrentAccessToken() != null;
    if (hasPreviousSession) {
      loginManager.logOut();
    }
    result.success(null);
  }

  /**
   * Enable Express Login
   *
   * @param activity
   * @param result flutter method channel result to send the response to the client
   */
  void expressLogin(Activity activity, final MethodChannel.Result result) {
    LoginManager.getInstance()
        .retrieveLoginStatus(
            activity,
            new LoginStatusCallback() {
              @Override
              public void onCompleted(AccessToken accessToken) {
                // User was previously logged in, can log them in directly here.
                // If this callback is called, a popup notification appears that says
                // "Logged in as <User Name>"
                HashMap<String, Object> data = getAccessToken(accessToken);
                result.success(data);
              }

              @Override
              public void onFailure() {
                // No access token could be retrieved for the user
                result.error("CANCELLED", "User has cancelled login with facebook", null);
              }

              @Override
              public void onError(Exception e) {
                // An error occurred
                result.error("FAILED", e.getMessage(), null);
              }
            });
  }

  /**
   * Get the facebook user data
   *
   * @param fields string of fields like "name,email,picture"
   * @param result flutter method channel result to send the response to the client
   */
  public void getUserData(String fields, final MethodChannel.Result result) {
    GraphRequest request =
        GraphRequest.newMeRequest(
            AccessToken.getCurrentAccessToken(),
            new GraphRequest.GraphJSONObjectCallback() {
              @Override
              public void onCompleted(JSONObject object, GraphResponse response) {
                try {
                  result.success(object.toString());
                } catch (Exception e) {
                  result.error("FAILED", e.getMessage(), null);
                }
              }
            });
    Bundle parameters = new Bundle();
    parameters.putString("fields", fields);
    request.setParameters(parameters);
    request.executeAsync();
  }

  /**
   * Resets the Facebook SDK application ID by reading it from the application's manifest file. This
   * method is used to automatically set the application ID when it is not explicitly provided. It
   * attempts to extract the application ID from the manifest file, and if it is prefixed with "fb",
   * it removes the "fb" prefix before setting the application ID.
   */
  private void resetApplicationId() {
    final Context applicationContext = FacebookSdk.getApplicationContext();
    final String applicationId;
    try {
      final ApplicationInfo appInfo =
          applicationContext
              .getPackageManager()
              .getApplicationInfo(
                  applicationContext.getPackageName(), PackageManager.GET_META_DATA);

      final Object appId = appInfo.metaData.get(APPLICATION_ID_PROPERTY);
      if (appId instanceof String) {
        final String appIdString = (String) appId;
        if (appIdString.toLowerCase(Locale.ROOT).startsWith("fb")) {
          applicationId = appIdString.substring(2);
        } else {
          applicationId = appIdString;
        }
      } else {
        throw new FacebookException(
            "App Ids cannot be directly placed in the manifest."
                + "They must be prefixed by 'fb' or be placed in the string resource file.");
      }
    } catch (final PackageManager.NameNotFoundException e) {
      return;
    }

    FacebookSdk.setApplicationId(applicationId);
  }
}
