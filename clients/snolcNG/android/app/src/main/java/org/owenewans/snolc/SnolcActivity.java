package org.owenewans.snolc;

import android.app.NativeActivity;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public final class SnolcActivity extends NativeActivity {
    private static final int VPN_PERMISSION = 1;
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String CIPHER = "AES/GCM/NoPadding";
    private static final String PREFERENCES = "snolc-profiles";
    private ConnectivityManager connectivityManager;
    private ConnectivityManager.NetworkCallback networkCallback;

    static {
        System.loadLibrary("snolc_ng");
    }

    public static native void nativeVpnReady(int fd);
    public static native void nativeVpnRevoked();
    public static native void nativeNetworkChanged();

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        networkCallback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network network) {
                nativeNetworkChanged();
            }

            @Override
            public void onLost(Network network) {
                nativeNetworkChanged();
            }
        };
        connectivityManager.registerDefaultNetworkCallback(networkCallback);
    }

    @Override
    protected void onDestroy() {
        if (connectivityManager != null && networkCallback != null) {
            connectivityManager.unregisterNetworkCallback(networkCallback);
        }
        super.onDestroy();
    }

    public boolean requestVpn() {
        runOnUiThread(this::prepareVpn);
        return true;
    }

    public boolean protectSocket(int fd) {
        return SnolcVpnService.protectSocket(fd);
    }

    public boolean storeCredential(String serverId, byte[] credential) {
        if (serverId == null || credential == null || credential.length == 0 || credential.length > 1024) {
            return false;
        }
        try {
            String name = credentialName(serverId);
            SecretKey key = credentialKey(name);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(credential);
            byte[] iv = cipher.getIV();
            if (iv.length == 0 || iv.length > 255) {
                return false;
            }
            ByteBuffer record = ByteBuffer.allocate(1 + iv.length + encrypted.length);
            record.put((byte) iv.length);
            record.put(iv);
            record.put(encrypted);
            String encoded = Base64.getEncoder().encodeToString(record.array());
            return getSharedPreferences(PREFERENCES, MODE_PRIVATE)
                    .edit()
                    .putString(name, encoded)
                    .commit();
        } catch (GeneralSecurityException | IllegalArgumentException error) {
            return false;
        } finally {
            Arrays.fill(credential, (byte) 0);
        }
    }

    public byte[] loadCredential(String serverId) {
        if (serverId == null) {
            return null;
        }
        try {
            String name = credentialName(serverId);
            String encoded = getSharedPreferences(PREFERENCES, MODE_PRIVATE).getString(name, null);
            if (encoded == null) {
                return null;
            }
            byte[] record = Base64.getDecoder().decode(encoded);
            if (record.length < 2) {
                return null;
            }
            ByteBuffer input = ByteBuffer.wrap(record);
            int ivLength = Byte.toUnsignedInt(input.get());
            if (ivLength == 0 || ivLength + 16 > input.remaining()) {
                return null;
            }
            byte[] iv = new byte[ivLength];
            input.get(iv);
            byte[] encrypted = new byte[input.remaining()];
            input.get(encrypted);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, credentialKey(name), new GCMParameterSpec(128, iv));
            byte[] credential = cipher.doFinal(encrypted);
            return credential.length > 0 && credential.length <= 1024 ? credential : null;
        } catch (GeneralSecurityException | IllegalArgumentException error) {
            return null;
        }
    }

    private SecretKey credentialKey(String name) throws GeneralSecurityException {
        KeyStore store = KeyStore.getInstance(KEYSTORE);
        try {
            store.load(null);
        } catch (IOException error) {
            throw new GeneralSecurityException(error);
        }
        if (store.containsAlias(name)) {
            return (SecretKey) store.getKey(name, null);
        }
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(
                name,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
        return generator.generateKey();
    }

    private static String credentialName(String serverId) throws GeneralSecurityException {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(serverId.getBytes(StandardCharsets.UTF_8));
        return "snolc.profile." + Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private void prepareVpn() {
        Intent permission = VpnService.prepare(this);
        if (permission == null) {
            startVpnService();
        } else {
            startActivityForResult(permission, VPN_PERMISSION);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_PERMISSION && resultCode == RESULT_OK) {
            startVpnService();
        } else if (requestCode == VPN_PERMISSION) {
            nativeVpnRevoked();
        }
    }

    private void startVpnService() {
        Intent service = new Intent(this, SnolcVpnService.class);
        if (Build.VERSION.SDK_INT >= 26) {
            startForegroundService(service);
        } else {
            startService(service);
        }
    }
}
