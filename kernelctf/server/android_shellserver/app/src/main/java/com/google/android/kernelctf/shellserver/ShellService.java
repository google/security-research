package com.google.android.kernelctf.shellserver;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;
import androidx.core.app.NotificationCompat;

import java.io.*;
import java.net.*;
import java.util.Arrays;

class ShellServer {
    private static final String TAG = "ShellServer";
    private String binaryPath;

    public ShellServer(String binaryPath) {
        this.binaryPath = binaryPath;
    }

    public void startServer(int port) throws IOException {
        ServerSocket serverSocket = new ServerSocket(port);
        Log.println(Log.INFO, TAG, "kernelCTF_READY");

        while (true) {
            Socket clientSocket = serverSocket.accept();
            new Thread(() -> handleClient(clientSocket)).start();
        }
    }

    private void handleClient(Socket clientSocket) {
        Log.println(Log.DEBUG, TAG, "BEFORE HANDLING");
        try {
            InputStream in = clientSocket.getInputStream();
            OutputStream out = clientSocket.getOutputStream();

            String[] finalCommand;
            
            if (binaryPath.equals("/system/bin/sh")) {
                // Default: interactive shell
                finalCommand = new String[]{"/system/bin/sh", "-i"};
                Log.println(Log.INFO, TAG, "Starting interactive shell");
            } else {
                // Custom program with fallback to interactive shell
                finalCommand = new String[]{
                    "/system/bin/sh", "-c", binaryPath
                };
                Log.println(Log.INFO, TAG, "Starting program: " + binaryPath + " (with shell fallback)");
            }

	    ProcessBuilder pb = new ProcessBuilder(finalCommand);

	    // Add /data/local/tmp to PATH so binaries there can be executed directly
	    String currentPath = pb.environment().get("PATH");
	    pb.environment().put("PATH", currentPath + ":/data/local/tmp");

	    pb.redirectErrorStream(true);

            Process process = pb.start();
            Log.println(Log.DEBUG, TAG, "AFTER STARTING PROCESS BUILDER with: " + Arrays.toString(finalCommand));

            InputStream processIn = process.getInputStream();
            OutputStream processOut = process.getOutputStream();

            // Thread to read from the client and write to the process
            Thread clientToProcessThread = new Thread(() -> {
                try {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        processOut.write(buffer, 0, bytesRead);
                        processOut.flush();
                    }
		    processOut.close(); // Signal EOF to shell
                } catch (IOException e) {
                     Log.println(Log.ERROR, TAG, "ERROR in clientToProcess: " + e);
	        } finally {
                     try { processOut.close(); } catch (IOException ignored) {}
                }
            });

            // Thread to read from the process and write to the client
            Thread processToClientThread = new Thread(() -> {
                try {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = processIn.read(buffer)) != -1) {
                        Log.println(Log.DEBUG, TAG, "BEFORE READING - bytes read = " + bytesRead);
                        out.write(buffer, 0, bytesRead);
                        Log.println(Log.DEBUG, TAG, "AFTER READING");
                        Log.println(Log.DEBUG, TAG, "STRING READ: " + Arrays.toString(buffer));
                        out.flush();
                    }
                } catch (IOException e) {
                     Log.println(Log.ERROR, TAG, "ERROR in processToClient: " + e.toString());
                } finally {
                    try { out.close(); } catch (IOException ignored) {}
                }
            });

            clientToProcessThread.start();
            processToClientThread.start();

            // Wait for the threads to finish
            clientToProcessThread.join();
            processToClientThread.join();

            process.destroy();
            clientSocket.close();

            Log.println(Log.INFO, TAG, "kernelCTF_DONE");

        } catch (IOException | InterruptedException e) {
            Log.println(Log.ERROR, TAG, "Exception in handleClient: " + e.toString());
        }
    }
}

public class ShellService extends Service {
    private static final String TAG = "ShellService";
    private static final String CHANNEL_ID = "ShellServiceChannel";
    private static final int NOTIFICATION_ID = 1;
    private ShellServer shellServer;
    private Thread shellServerThread;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String server_port_arg = intent.getStringExtra("server_port");

        if (server_port_arg == null) {
            Log.println(Log.ERROR, TAG, "No Port passed in arguments");
            stopSelf();
            return START_NOT_STICKY;
        }

	String binary_path = intent.getStringExtra("binary_path");

        int server_port = Integer.parseInt(server_port_arg);

        // Create and show foreground notification
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("Shell Server Running")
                .setContentText("Port: " + server_port + " | Binary: " + binary_path)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build();

        startForeground(NOTIFICATION_ID, notification);

        // Start shell server thread
	shellServerThread = new Thread(() -> {
            shellServer = new ShellServer(binary_path);
            try {
                shellServer.startServer(server_port);
            } catch (IOException e) {
                Log.println(Log.ERROR, TAG, "IOEXCEPTION: " + e.toString());
            }
        });
        shellServerThread.start();

        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();

        if (shellServerThread != null) {
            shellServerThread.interrupt();
        }

        Log.println(Log.INFO, TAG, "ShellService destroyed");
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Shell Server Service",
                    NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("Keeps shell server running in background");

            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }
}
