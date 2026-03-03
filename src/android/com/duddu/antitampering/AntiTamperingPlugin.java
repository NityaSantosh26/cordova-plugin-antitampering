package com.duddu.antitampering;

import android.app.Activity;
import android.content.pm.ApplicationInfo;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.LOG;
import org.apache.cordova.PluginResult;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

public class AntiTamperingPlugin extends CordovaPlugin {

    public static final String PLUGIN_NAME = "TamperDetection";
    public static final String SHA_FINGERPRINT_PROP = "TrustedSigningSHAFingerprint";
    private Activity activity;

    @Override
    public void pluginInitialize() {
        activity = cordova.getActivity();

        // Skip all checks on debuggable (local debug) builds
        if (isDebuggableBuild()) {
            LOG.i(PLUGIN_NAME, "Debuggable build detected. Skipping anti-tampering checks.");
            super.pluginInitialize();
            return;
        }

        checkAndStopExecution();
        super.pluginInitialize();
    }

    private boolean isDebuggableBuild() {
        try {
            ApplicationInfo ai = activity.getApplicationInfo();
            return (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        } catch (Exception ignored) {
            // If we can't determine it, default to not skipping
            return false;
        }
    }

    private void checkAndStopExecution() {
        try {
            AssetsIntegrity.checkForPackageID(activity);
            AssetsIntegrity.check(activity.getAssets());

            DebugDetection.check(activity.getPackageName());

            String trustedSHA = preferences.getString(SHA_FINGERPRINT_PROP, "");
            if (!trustedSHA.isEmpty()) {
                SigningCertificateCheck.check(trustedSHA, activity.getPackageName(), activity.getPackageManager());
            } else {
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

                        if (isDebuggableBuild()) {
                            response.put("skipped", true);
                            response.put("reason", "debuggable_build");
                            result = new PluginResult(PluginResult.Status.OK, response);
                            callbackContext.sendPluginResult(result);
                            return;
                        }

                        response.put("skipped", false);

                        AssetsIntegrity.checkForPackageID(activity);
                        response.put("assets", AssetsIntegrity.check(activity.getAssets()));

                        DebugDetection.check(activity.getPackageName());

                        String trustedSHA = preferences.getString(SHA_FINGERPRINT_PROP, "");
                        if (!trustedSHA.isEmpty()) {
                            response.put(
                                "signingCertificateCheck",
                                SigningCertificateCheck.check(trustedSHA, activity.getPackageName(), activity.getPackageManager())
                            );
                        } else {
                            LOG.i(PLUGIN_NAME, "Skipping signing certificate check as TRUSTED_SHA_VALUE is empty.");
                            response.put("signingCertificateCheck", JSONObject.NULL);
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
