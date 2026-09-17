package org.owenewans.snolc;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.VpnService;
import android.os.IBinder;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import java.io.IOException;

public final class SnolcVpnService extends VpnService {
    private static final String CHANNEL = "snolc-vpn";
    private static volatile SnolcVpnService active;
    private ParcelFileDescriptor tunnel;

    public static boolean protectSocket(int fd) {
        SnolcVpnService service = active;
        return service != null && service.protect(fd);
    }

    @Override
    @SuppressWarnings("deprecation")
    public void onCreate() {
        super.onCreate();
        active = this;
        NotificationManager notifications = getSystemService(NotificationManager.class);
        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= 26) {
            notifications.createNotificationChannel(new NotificationChannel(
                    CHANNEL,
                    "snolc VPN",
                    NotificationManager.IMPORTANCE_LOW));
            builder = new Notification.Builder(this, CHANNEL);
        } else {
            builder = new Notification.Builder(this);
        }
        Notification notification = builder.setContentTitle("snolcNG")
                    .setContentText("VPN active")
                    .setSmallIcon(android.R.drawable.stat_sys_warning)
                    .setOngoing(true)
                    .build();
        startForeground(1, notification);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (tunnel == null) {
            tunnel = new Builder()
                    .setSession("snolcNG")
                    .setMtu(1280)
                    .addAddress("10.0.0.2", 32)
                    .addAddress("fd00::2", 128)
                    .addRoute("0.0.0.0", 0)
                    .addRoute("::", 0)
                    .addDnsServer("1.1.1.1")
                    .establish();
            if (tunnel == null) {
                SnolcActivity.nativeVpnRevoked();
                stopSelf();
                return START_NOT_STICKY;
            }
            SnolcActivity.nativeVpnReady(tunnel.getFd());
        }
        return START_STICKY;
    }

    @Override
    public void onRevoke() {
        SnolcActivity.nativeVpnRevoked();
        closeTunnel();
        stopSelf();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        active = null;
        closeTunnel();
        SnolcActivity.nativeVpnRevoked();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return super.onBind(intent);
    }

    private void closeTunnel() {
        if (tunnel != null) {
            try {
                tunnel.close();
            } catch (IOException ignored) {
            }
            tunnel = null;
        }
    }
}
