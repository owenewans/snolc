package org.owenewans.snolc;

import android.app.NativeActivity;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Build;

public final class SnolcActivity extends NativeActivity {
    private static final int VPN_PERMISSION = 1;
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
