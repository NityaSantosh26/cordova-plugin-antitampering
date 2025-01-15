package com.duddu.antitampering;

import android.app.Activity;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.LOG;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

public class AntiTamperingPlugin extends CordovaPlugin {

    public static  final  String PLUGIN_NAME = "TamperDetection";
    private Activity activity;

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        activity = cordova.getActivity();
//      checkAndStopExecution();
        super.initialize(cordova, webView);
    }

    private void checkAndStopExecution() {
        try {
            // Checking assets integrity
            AssetsIntegrity.check(activity.getAssets());
            DebugDetection.check(activity.getPackageName());

            // Perform signing certificate check if the SHA is provided
            String trustedSHA = preferences.getString("TrustedSigningSHAFingerprint", "");
            if (!trustedSHA.isEmpty()) {
                // Perform SHA check only if a trusted SHA is provided
                SigningCertificateCheck.check(trustedSHA, activity.getPackageName(), activity.getPackageManager());
            }
            else {
                // If the trusted SHA is empty, skip the check
                LOG.i(PLUGIN_NAME, "Skipping signing certificate check as TRUSTED_SHA_VALUE is empty.");
            }
        } catch (final Exception e) {
            cordova.getActivity().runOnUiThread(new Runnable() {
                public void run () {
                    e.printStackTrace();
                    throw new TamperingException("Anti-Tampering check failed");
                }
            });
        }
    }

    @Override
    public boolean execute(String action, JSONArray args, final CallbackContext callbackContext) throws JSONException {
        if ("verify".equals(action)) {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run () {
                    PluginResult result;
                    try {
                        JSONObject response = new JSONObject();
                        AssetsIntegrity.checkForPackageID(activity);
                        // If everything goes well, verify assets integrity
                        response.put("assets", AssetsIntegrity.check(activity.getAssets()));

                        // Fetching trusted SHA from preferences
                        String trustedSHA = preferences.getString("TrustedSigningSHAFingerprint", "");

                        // Perform certificate check if SHA is available
                        if (!trustedSHA.isEmpty()) {
                            SigningCertificateCheck.check(trustedSHA, activity.getPackageName(), activity.getPackageManager());
                        }
                        else {
                            // If the trusted SHA is empty, skip the check
                            LOG.i(PLUGIN_NAME, "Skipping signing certificate check as TRUSTED_SHA_VALUE is empty.");
                        }

                        result = new PluginResult(PluginResult.Status.OK, response);
                    } catch (Exception e) {
                        result = new PluginResult(PluginResult.Status.ERROR, e.toString());
                    }
                    callbackContext.sendPluginResult(result);
                }
            });
            return true;
        }

        return false;
    }
}
