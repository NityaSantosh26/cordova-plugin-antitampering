package com.duddu.antitampering;

import android.annotation.SuppressLint;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.SigningInfo;
import android.content.pm.Signature;
import android.os.Build;

import org.json.JSONObject;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class SigningCertificateCheck {
    public static JSONObject check(String trustedSignature, String packageName, PackageManager packageManager) throws Exception {
        String TRUSTED_SIGNATURE = trustedSignature.toLowerCase();
        String currentFingerprint = getCertificateFingerprint(packageName, packageManager);

        boolean checkForMatch = TRUSTED_SIGNATURE.equals(currentFingerprint);
        JSONObject result = new JSONObject();
        result.put("match", checkForMatch);

        if (!checkForMatch) {
            throw new Exception("App has been re-signed or tampered with");
        }

        return result;
    }

    @SuppressLint("ObsoleteSdkInt")
    private static String getCertificateFingerprint(String packageName, PackageManager packageManager) throws Exception {
        PackageInfo packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES);

        Signature[] signatures;
        if (Build.VERSION_CODES.P <= Build.VERSION.SDK_INT) {
            SigningInfo signingInfo = packageInfo.signingInfo;
            if (signingInfo == null) {
                throw new Exception("No signing information found");
            }
            if (signingInfo.hasMultipleSigners()) {
                // If multiple signers are present, get all signatures
                signatures = signingInfo.getApkContentsSigners();
            } else {
                // Otherwise, get the signing certificate
                signatures = signingInfo.getSigningCertificateHistory();
            }
        } else {
            // Fallback for older versions
            signatures = packageInfo.signatures;
        }

        if (signatures == null || signatures.length == 0) {
            throw new Exception("No signature found");
        }

        // Get the first signature (or handle multiple signatures as needed)
        Signature signature = signatures[0];
        return getSHA256Fingerprint(signature.toByteArray());
    }

    private static String getSHA256Fingerprint(byte[] certificate) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(certificate);
        StringBuilder hexString = new StringBuilder();
        for (byte b : digest) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
