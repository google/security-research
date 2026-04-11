package com.google.android.kernelctf.shellserver;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "ShellService";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent intent = getIntent();
        String server_port_arg = intent.getStringExtra("server_port");

        if (server_port_arg == null) {
            Log.println(Log.ERROR, TAG, "No Port passed in arguments; try passing server_port as an extra string to the intent.");
            finish();
            return;
        }

	// Get binary path, default to toybox bash if not provided
        String binary_path = intent.getStringExtra("binary_path");
        if (binary_path == null) {
            binary_path = "/system/bin/sh";
            Log.println(Log.INFO, TAG, "No binary_path provided, using default: " + binary_path);
        } else {
            Log.println(Log.INFO, TAG, "Using binary_path: " + binary_path);
        }

        // Start the foreground service
        Intent serviceIntent = new Intent(this, ShellService.class);
        serviceIntent.putExtra("server_port", server_port_arg);
        serviceIntent.putExtra("binary_path", binary_path);
        startForegroundService(serviceIntent);

        Log.println(Log.INFO, TAG, "ShellService started from MainActivity");

        // Close the activity - service will continue running in background
        finish();
    }
}
