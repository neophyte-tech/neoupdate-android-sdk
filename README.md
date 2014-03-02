neoupdate-android-sdk
=====================

## Introduction

Use this library to integrate an app with neoUpdate (http://neoupdate.mobi) platform.

## Using the SDK

To use this library follow these steps:

1. Drop in the jar or the neoUpdate.java file/class into your project.
2. Extend the neoUpdate class and implement/extend onProgress() and onPostExecute() if required. onProgress receives the current completion status (multiply the value by 100 for percentage completion). onPostExecute receives the status as a string "Success" for successful completion or error string (sometimes what the server returns) on failure.
3. Initialize the parameters (like tokens & secrets) and call execute


## Example

```java
package com.neoexample.updateexample;

import android.os.Bundle;
import android.app.Activity;
import android.content.Context;
import android.util.Log;
import android.view.Menu;

public class UpdateActivity extends Activity {
	private static final String TAG = "[neoUpdateDemo]";

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_update);

        String appToken = "[Use your token here]";
        String appSecret = "[Use your secret here]";
        // For Online Updation
		Update update = new Update(getApplicationContext(),
                                   "/download/com.neoexample.updateexample/",
                                   "/sdcard/tmp/",
                                   appToken,
                                   appSecret,
                                   1);
        // For Offline Updation - comment out the previous line
		// Update update = new Update(getApplicationContext(),
        //                            "file:////sdcard/update/update.npk",
        //                            "/sdcard/tmp/",
        //                            null, null, 0);
		update.execute();
	}

	private class Update extends neoUpdate {
		public Update(Context c, String baseUrl, String tmpDir,
					   String appToken, String appSecret, int nSimultaneousConnections) {
			super(c, baseUrl, tmpDir, appToken, appSecret, nSimultaneousConnections);
		}

		@Override
		protected void onProgressUpdate(Float... values) {
			Log.d(TAG, "onProgressUpdate: "+values[0]);
		}

		@Override
		protected void onPostExecute(String result) {
			Log.d(TAG,"Result: "+result);
		}
	}
}

```
