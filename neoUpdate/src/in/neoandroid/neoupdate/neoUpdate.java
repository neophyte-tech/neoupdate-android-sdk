package in.neoandroid.neoupdate;

/*
neoUpdate Android SDK: neoUpdate.java

Copyright (C) 2013-2014 Neophyte Technologies LLP & Respective Contributors
See contributors.txt for complete list of contributors.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.DigestInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.concurrent.locks.ReentrantLock;
import java.util.zip.GZIPInputStream;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONArray;
import org.json.JSONObject;

import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.net.Uri;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.os.Environment;
import android.provider.Settings;
import android.util.Base64;
import android.util.Log;
import android.webkit.MimeTypeMap;
import static android.provider.BaseColumns._ID;

public class neoUpdate extends AsyncTask<Void, Float, String> {
	private final double neoUpdateVersion = 1.0f;
	private final static boolean enableDebug = true;
	private final static String TAG = "[neoUpdate]";
	private final String serverUrl = "https://neoupdate-in.appspot.com";
	private String baseUrl;
	private int nConnections; /**< if 0 -> assumes local filesystem */
	private ArrayList<NewAsset> filesToDownload;
	private String tmpDir;
	private Boolean stopped;
	private String appToken;
	private String appSecret;
	private int totalFilesToDownload;
	private String deviceID;
	private String serialNo;
	private String macAddress;
	private Context context;
	private PackageInfo packageInfo;
	private NewAsset apkUpdatePath;
	private neoUpdateDB db;
	private ReentrantLock lock;
	private Boolean fromOfflineStorage = false;
	private Boolean fromNPKStorage = false;
	
	// File list
	private final String metafile = "/neoupdate.json";
	
	/**
	 * file:// implies local filesystem
	 * @param baseUrl
	 * @param tmpDir
	 * @param nSimultaneousConnections
	 */
	public neoUpdate(Context c, String baseUrl, String tmpDir, String appToken, String appSecret, int nSimultaneousConnections) {
		this.baseUrl = baseUrl;
		this.tmpDir = tmpDir;
		this.appToken = appToken;
		this.appSecret = appSecret;
		nConnections = nSimultaneousConnections;
		context = c;
		if(nConnections <= 0)
			nConnections = 1;
		// Check for local filesystem
		if(baseUrl.startsWith("file:///") || appToken == null || appSecret == null) {
			nConnections = 0;
			this.baseUrl = baseUrl.replace("file:///", "/");
			fromOfflineStorage = true;
			if(baseUrl.endsWith(".npk"))
				fromNPKStorage = true;
		} else {
			this.baseUrl = serverUrl+baseUrl;
			if(this.baseUrl.endsWith("/"))
				this.baseUrl = this.baseUrl.substring(0, this.baseUrl.length()-1);
			lock = new ReentrantLock();
		}
		filesToDownload = new ArrayList<NewAsset>();
		deviceID = Settings.Secure.getString(c.getContentResolver(), Settings.Secure.ANDROID_ID);
		serialNo = neoUpdate.getSerialNo();
		macAddress = getWifiMac(c);
		if(deviceID == null) deviceID = "";
		if(serialNo == null) serialNo = "";
		if(macAddress == null) macAddress = "";
		try {
			packageInfo = c.getPackageManager().getPackageInfo(c.getPackageName(), 0);
		} catch(Exception e) { }
		db = new neoUpdateDB(c);
		stopped = false;
		totalFilesToDownload = 0;
		if(enableDebug) {
			Log.d(TAG, "DeviceID: "+deviceID);
			Log.d(TAG, "serialNo: "+serialNo);
			Log.d(TAG, "MAC Address: "+macAddress);
			Log.d(TAG, "SDCard: "+Environment.getExternalStorageDirectory().getAbsolutePath());
			Log.d(TAG, "Data: "+Environment.getDataDirectory().getAbsolutePath());
		}
	}
	
	private String getMetaFromNPK() {
		try {
			GZIPInputStream npkFile = new GZIPInputStream(new FileInputStream(baseUrl));
			//FileInputStream npkFile = new FileInputStream(baseUrl);
			TarArchiveInputStream input = new TarArchiveInputStream(npkFile);
			TarArchiveEntry ae;
			while((ae = input.getNextTarEntry())!=null) {
				if(ae.isDirectory())
					Log.e("[neoUpdate]", "Dir: "+ae.getName());
				else
					Log.e("[neoUpdate]", "File: "+ae.getName());
				if(ae.getName().equalsIgnoreCase("neoupdate.json")) {
					byte buff[] = new byte[(int) ae.getSize()]; 
					input.read(buff);
					input.close();
					return new String(buff);
				}
			}
			input.close();
		} catch(Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	private void startUpdateApk(Uri installerUri) {
		MimeTypeMap myMime = MimeTypeMap.getSingleton();
		String mimeType = myMime.getMimeTypeFromExtension("apk");
		Intent intent = new Intent(Intent.ACTION_VIEW);
		intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
		intent.setDataAndType(installerUri, mimeType);//"application/vnd.android.package-archive");
		context.startActivity(intent);
	}
	
	public static String getDeviceID(Context c) {
		return Settings.Secure.getString(c.getContentResolver(), Settings.Secure.ANDROID_ID);
	}
	
	public static String getWifiMac(Context c) {
		try {
			WifiManager wifiMgr = (WifiManager) c.getSystemService(Context.WIFI_SERVICE);
			return wifiMgr.getConnectionInfo().getMacAddress();
		} catch(Exception e) { }
		return null;
	}
	
	private boolean checkSignature(String jsonContent, String sign) {
		Log.d(TAG, "JSON: "+jsonContent);

		if( sign == null)
			return false;
		final String publicKeyStr = 
						"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq+6EG/fAE+zIdh5Wzqnf"+
					    "Fo4nCf7t7eJcKyvk1lqX1MdkIi/fUs8HQ4aQ4jWLCO4M1Gkz1FQiXOnheGLV5MXY"+
					    "c9GyaglsofvpA/pU5d16FybX2pCevbTzcm39eU+XlwQWOr8gh23tYD8G6uMX6sIJ"+
					    "W+1k1FWdud9errMVm0YUScI+J4AV5xzN0IQ29h9IeNp6oFqZ2ByWog6OBMTUDFIW"+
					    "q8oRvH0OuPv3zFR5rKwsbTYb5Da8lhUht04dLBA860Y4zeUu98huvS9jQPu2N4ns"+
					    "Hf425FfDJ/wae+7eLdQo7uFb+Wvc+PO9U39e6vXQfa8ZkUoXHD0XZN4jsFcKYuJw"+
					    "OwIDAQAB";
		try {
			byte keyBytes[] = Base64.decode(publicKeyStr.getBytes(), Base64.NO_WRAP);

			X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PublicKey publicKey =  kf.generatePublic(publicSpec);

			Signature signer = Signature.getInstance("SHA1withRSA");
			signer.initVerify(publicKey);
			signer.update(jsonContent.getBytes(), 0, jsonContent.length());

			return signer.verify(Base64.decode(sign, Base64.NO_WRAP));
		} catch (Exception e) { }
		return false;
	}
	
	/* -- Works only with Android 2.3+ */
	public static String getSerialNo() {
		//return android.os.SystemProperties.get("ro.serialno", "unknown");
		try {
			Class<?> c = Class.forName("android.os.SystemProperties");       
			Method get = c.getMethod("get", String.class, String.class );     
			return (String) (get.invoke(c, "ro.serialno", ""));
		} catch(Exception e) { }
		return "";
	}

    /**
     * A Simpler HTTPConnection helper.
     * Used currently.
     */
	private static HttpURLConnection getHTTPConnection(String url) throws MalformedURLException, IOException {
		HttpURLConnection c;
		c = (HttpURLConnection) new URL(url).openConnection();
		c.setUseCaches(false);
		c.connect();
		return c;
	}

	public HttpResponse HttpWithPostData(String api, long fromBytes) {
		String url = baseUrl+api;
		try {
			url = baseUrl+URLEncoder.encode(api, "UTF-8");
		} catch(Exception e) {
			if(enableDebug)
				e.printStackTrace();
			url = baseUrl+api;
		}
	    // Create a new HttpClient and Post Header
	    HttpClient httpclient = new DefaultHttpClient();
	    HttpPost httppost = new HttpPost(url);
	    Log.d(TAG, "HTTP Fetch: "+url+" with Resume: "+fromBytes);
	    
	    if(appToken == null || appSecret == null || appToken.length() == 0 || appSecret.length() == 0)
	    	return null;
	    if(deviceID.length() == 0 && serialNo.length() == 0 && macAddress.length() == 0)
	    	return null;

	    try {
	    	// For resuming downloads
	    	if(fromBytes > 0)
	    		httppost.addHeader(new BasicHeader("Range","bytes="+fromBytes+"-"));
	        // Add post data
	        ArrayList<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(2);
	        nameValuePairs.add(new BasicNameValuePair("APP_TOKEN", appToken));
	        nameValuePairs.add(new BasicNameValuePair("APP_SECRET", appSecret));
	        if(deviceID != null)
	        	nameValuePairs.add(new BasicNameValuePair("DEVICE_ID", deviceID));
	        if(serialNo != null)
	        	nameValuePairs.add(new BasicNameValuePair("DEVICE_SERIAL", serialNo));
	        if(macAddress != null)
	        	nameValuePairs.add(new BasicNameValuePair("DEVICE_MAC", macAddress));
	        httppost.setEntity(new UrlEncodedFormEntity(nameValuePairs));

	        // Execute HTTP Post Request
	        return  httpclient.execute(httppost);
	    } catch (ClientProtocolException e) {
	        e.printStackTrace();
	    } catch (IOException e) {
	        e.printStackTrace();
	    }
	    return null;
	}
	
	private static String inputStreamToString(InputStream is) {
	    String line = "";
	    StringBuilder total = new StringBuilder();	    
	    BufferedReader rd = new BufferedReader(new InputStreamReader(is));

	    try {
		    while ((line = rd.readLine()) != null) 
		        total.append("\n"+line); 
	    } catch(Exception e) { 
	    	e.printStackTrace();
	    };
	    
	    return total.toString();
	}
	
	public int totalFilesToDownload() {
		return totalFilesToDownload;
	}
	
	public int filesToDownload() {
		return filesToDownload.size();
	}
	
	/**
	 * Stops the update procedure.
	 * @return Success/failure
	 */
	public Boolean stopUpdate() {
		stopped = true;
		return true;
	}
	
	public static Boolean isDevicePresent(Context c, String device) {
		neoUpdateDB db = new neoUpdateDB(c);
		return db.isDevicePresent(device);
	}
	
	private InputStream getLocalFile(String path) throws FileNotFoundException {
		FileInputStream file = new FileInputStream(path);
		return file;
	}

	private JSONObject downloadMetafile() {
		// TODO: Check for resuming download (?) - Not necessary for metafiles ?
		try {
			String str = null;
			if(nConnections == 0 || fromOfflineStorage) {
				if(fromNPKStorage)
					str = getMetaFromNPK();
				else
					str = inputStreamToString(getLocalFile(baseUrl+metafile));
			}
			else {
				HttpResponse res = HttpWithPostData(metafile, 0);
				if(res != null)
					str = inputStreamToString(res.getEntity().getContent());
			}
			if(str == null)
				return null;
			String sign = str.substring(str.lastIndexOf('\n')).trim();
			str = str.substring(0, str.lastIndexOf('\n')).trim();
			if(!checkSignature(str, sign)) {
				Log.e(TAG, "Signature Verification failed!");
				return null;
			}
			return new JSONObject(str);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private Boolean parseMetafile(JSONObject metafile) {
		double version;
		boolean forceVersion;
		boolean allowed = false;
		try {
			version = metafile.getDouble("version");
			forceVersion = metafile.getBoolean("forceVersion");
			JSONObject appDetails = metafile.getJSONObject("app");
			JSONArray assets = metafile.getJSONArray("assets");
			JSONArray devices = metafile.getJSONArray("allowedDevices");

			int nAssets = assets.length();
			String packageName = appDetails.getString("packageName");
			int versionCode = appDetails.getInt("versionCode");
			String apkPath = appDetails.getString("APK");
			boolean offlineSupport = appDetails.getBoolean("offlineSupport");
			
			if(enableDebug) {
				Log.d(TAG,"Version: "+version+":"+neoUpdateVersion);
				Log.d(TAG,"Package Name: "+packageName+":"+packageInfo.packageName);
				Log.d(TAG,"APK Path: "+apkPath);
			}

			// Check if it is being updated using offline storage
			if(!offlineSupport && fromOfflineStorage) {
				Log.e(TAG, "Updating from offline storage is disabled for this app?");
				return false;
			}

			db.clearDevicesList();
			for(int i=0;i<devices.length();i++) {
				String device = devices.getString(i);
				if(device.length() > 0 && deviceID.compareToIgnoreCase(device) == 0)
					allowed = true;
				db.insertDevice(device);
				if(enableDebug)
					Log.d(TAG,"Device Allowed: "+device);
			}
			
			
			// DeviceID or signature error
			if(!allowed)
				return false;

			apkUpdatePath = null;
			if(version > neoUpdateVersion && forceVersion) {
				Log.e(TAG,"neoUpdate seems to be of older version! Required: "+version+" Current: "+neoUpdateVersion);
				return false;
			}
			
			if(packageInfo.packageName.compareTo(packageName) != 0) {
				Log.e(TAG, "PackageNames don't seem to match - url for some other app? Provided: "+packageName);
				return false;
			}
			
			if(packageInfo.versionCode < versionCode) {
				// APK Update Required - Lets first do that
				apkUpdatePath = new NewAsset();
				apkUpdatePath.path = apkPath;
				apkUpdatePath.md5 = appDetails.getString("md5");
				return true;
			}
						
			// Parse the assets
			for(int i=0;i<nAssets;i++) {
				JSONObject obj = assets.getJSONObject(i);
				NewAsset asset = new NewAsset();
				asset.path = obj.getString("path");
				asset.md5 = obj.getString("md5");

				// Ignore already downloaded files
				if(db.updateAndGetStatus(asset.path, asset.md5) == neoUpdateDB.UPDATE_STATUS.UPDATE_COMPLETE)
					continue;
				filesToDownload.add(asset);
				if(enableDebug) {
					Log.d(TAG, "Enqueued: "+asset.path+" With MD5: "+asset.md5);
				}
			}
			totalFilesToDownload = filesToDownload.size();
		} catch(Exception e) { 
			if(enableDebug)
				e.printStackTrace();
			return false;
		}
		return true;
	}
	
	private String mapPath(String path) {
		String ret = path;
		if(path.startsWith("/sdcard/"))
			path.replaceFirst("/sdcard/",Environment.getExternalStorageDirectory().getAbsolutePath()+"/");
		if(path.startsWith("/data/"))
			path.replaceFirst("/data/",Environment.getDataDirectory().getAbsolutePath()+"/");
		return ret;
	}
	
	private void createSubDirectories(String path) {
		try {
			File newDir = new File(path.substring(0, path.lastIndexOf('/')));
			newDir.mkdirs();
		} catch(Exception e) {
			if(enableDebug)
				e.printStackTrace();
		}
	}
	
	private boolean downloadFile(NewAsset asset, String toPath) {
		return downloadFile(asset, toPath, null, null);
	}
	
	private boolean downloadFile(NewAsset asset, String toPath, TarArchiveInputStream tin, TarArchiveEntry ae ) {
		if(enableDebug)
			Log.d(TAG,"Start download: "+asset.path + ":NPK: "+(tin!=null));
		boolean resume = (db.updateAndGetStatus(asset.path, asset.md5) == neoUpdateDB.UPDATE_STATUS.UPDATE_RESUME);
		String newPath;
		if(toPath != null)
			newPath = toPath;
		else
			newPath = mapPath(asset.path);
		createSubDirectories(newPath);
		File newFile = new File(newPath);
		long fromBytes = 0;
		if(resume)
			fromBytes = newFile.length();

		try {
			FileOutputStream os = new FileOutputStream(newFile, resume);
			db.setMd5(asset.path, asset.md5);

			if(tin != null && ae != null) {
				// Via NPK
				final int BUFF_SIZE = (8*1024); // Buffer size of 8KB
				byte[] buffer = new byte[BUFF_SIZE];
				int n = 0;
				long size = ae.getSize();
				if(resume && fromBytes > 0 && fromBytes < size) {
					tin.skip(fromBytes);
					size -= fromBytes;
				}
				while(size > 0) {
					n = BUFF_SIZE;
					if( n > size)
						n = (int)size;
					n = tin.read(buffer, 0, n);
					if(n < 0)
						break;
					if(n > 0)
						os.write(buffer, 0, n);
				}
			}
			else if(nConnections <= 0) {
				// Via Local File System
				FileInputStream is = new FileInputStream(baseUrl+asset.path);
				is.getChannel().transferTo(fromBytes, is.getChannel().size()-fromBytes, os.getChannel());
				is.close();
			} else {
				// Via Internet
				HttpResponse resp = HttpWithPostData(asset.path, fromBytes);
				resp.getEntity().writeTo(os);
			}
			db.setDownloaded(asset.path, true);
			os.close();
		}
		catch(Exception e) {
			if(enableDebug)
				e.printStackTrace();
			return false;
		}
		return true;
	}
	
	private String processFromLocalStorage() {
		while(filesToDownload.size() > 0 && !stopped) {
			NewAsset asset = filesToDownload.remove(0);
			if(!downloadFile(asset, null)) {
				Log.e(TAG,"File download failed!");
				return "Unable to find the required file: "+asset.path;
			}
			publishProgress((float)(totalFilesToDownload-filesToDownload.size())/(float)totalFilesToDownload);
		}
		return "Success";
	}
	
	private NewAsset findAndGetAsset(String path) {
		for(NewAsset asset:filesToDownload) {
			if(asset.path.equalsIgnoreCase(path)) {
				filesToDownload.remove(asset);
				return asset;
			}
		}
		return null;
	}

	private String processFromNPK() {
		try {
			GZIPInputStream npkFile = new GZIPInputStream(new FileInputStream(baseUrl));
			//FileInputStream npkFile = new FileInputStream(baseUrl);
			TarArchiveInputStream input = new TarArchiveInputStream(npkFile);
			TarArchiveEntry ae;
			while((ae = input.getNextTarEntry())!=null && filesToDownload.size() > 0 && !stopped) {
				if(ae.isDirectory()) {
					Log.e("[neoUpdate]", "Dir: "+ae.getName());
				} else {
					Log.e("[neoUpdate]", "File: "+ae.getName());
					String filename = ae.getName();
					NewAsset asset = findAndGetAsset(filename);
					if(asset != null) {
						downloadFile(asset, null, input, ae);
						publishProgress((float)(totalFilesToDownload-filesToDownload.size())/(float)totalFilesToDownload);
					}
				}
			}
			input.close();
		} catch(Exception e) {
			e.printStackTrace();
			return "Unknown Error: Update Failed!";
		}
		return "Success";
	}
	
	private boolean downloadAPKFromNPK() {
		try {
			String apkName = apkUpdatePath.path.replace("/", "");
			GZIPInputStream npkFile = new GZIPInputStream(new FileInputStream(baseUrl));
			//FileInputStream npkFile = new FileInputStream(baseUrl);
			TarArchiveInputStream input = new TarArchiveInputStream(npkFile);
			TarArchiveEntry ae;
			while((ae = input.getNextTarEntry())!=null) {
				if(!ae.isDirectory() && ae.getName().equalsIgnoreCase(apkName)) {
					String apkPath = tmpDir+apkUpdatePath.path;
					boolean status = downloadFile(apkUpdatePath, apkPath, input, ae);
					input.close();
					return status;
				}
			}
			input.close();
		} catch(Exception e) {
			e.printStackTrace();
		}

		return false;
	}

	@Override
	protected String doInBackground(Void... params) {
		JSONObject metafile = downloadMetafile();
		if(metafile == null)
			return "Could not download meta data. Please check the connection";
		if(!parseMetafile(metafile))
			return "Failed to authenticate the device or Failed to parse metadata.";
		
		if(apkUpdatePath != null) {
			String apkPath = "";
			if(fromNPKStorage) {
				apkPath = tmpDir+apkUpdatePath.path.replace("/", "");
				if(!downloadAPKFromNPK())
					return "Unable to save APK!";
			} else if(nConnections <= 0) {
				apkPath = baseUrl+apkUpdatePath.path;
			} else {
				apkPath = tmpDir+apkUpdatePath.path.substring(apkUpdatePath.path.lastIndexOf('/'));
				if(!downloadFile(apkUpdatePath, apkPath)) {
					return "Unable to download APK!";
				}
			}
			startUpdateApk(Uri.parse("file:///"+apkPath));
			return "APK Updated. Please re-run update after restarting the app to continue update";
		}
		if(nConnections > 0) {
			long waitTime = 1000/nConnections;
			if(waitTime <= 0)
				waitTime = 1;
			Thread threads[] = new Thread[nConnections];
			int i;
			for(i=0;i<nConnections;i++) {
				threads[i] = new Thread(new DownloadRunnable());
				threads[i].start();
			}
			while(!stopped) {
				if(totalFilesToDownload > 0) {
					float nComplete = (totalFilesToDownload-filesToDownload.size()-nConnections);
					if(nComplete >= 0)
						publishProgress(nComplete/(float)totalFilesToDownload);
				}
				boolean inprogress = false;
				for(i=0;i<nConnections;i++) {
					try {
						threads[i].join(waitTime);
					} catch(Exception e) { }
					inprogress = inprogress || threads[i].isAlive();
				}
				if(!inprogress)
					break;
				if(stopped && filesToDownload.size() > 0) {
					lock.lock();
					filesToDownload.clear();
					lock.unlock();
				}
			}
		} else {
			if(fromNPKStorage)
				return processFromNPK();
			return processFromLocalStorage();
		}
		
		return "Success";
	}
	
	private static class neoUpdateDB extends SQLiteOpenHelper {
		private final static String DB_NAME = "neoUpdateDB";
		private final static int DB_VERSION = 1;
		private final static String TABLE_NAME = "neoUpdate";
		private final static String COL_PATH = "PATH";
		private final static String COL_MD5 = "MD5";
		private final static String COL_DOWNLOADED = "DOWNLOADED";
		private final static String DEVICES_TABLE = "neoDevices";
		private final static String COL_DEVICES = "DEVICES";
		
		private SQLiteDatabase neoDB; 
		
		public static enum UPDATE_STATUS {
			UPDATE_REQUIRED,
			UPDATE_RESUME,
			UPDATE_COMPLETE
		};

		public neoUpdateDB(Context context) {
			super(context, DB_NAME, null, DB_VERSION);
			neoDB = getWritableDatabase();
		}
		
		public void insertDevice(String device) {
			ContentValues cv = new ContentValues();
			cv.put(COL_DEVICES, device);
			neoDB.insert(DEVICES_TABLE, null, cv);
		}
		
		public Boolean isDevicePresent(String device) {
			Cursor c = neoDB.query(DEVICES_TABLE, new String[] {COL_DEVICES}, 
					COL_DEVICES+"=?", new String[]{device}, null, null, null, "1");
			if(c != null && c.getCount() > 0) {
				c.close();
				return true;
			}
			return false;
		}
		
		/**
		 * Call this after completion of the download (Or to pause and resume the download later)
		 * @param path Path of the file
		 * @param status True to set it as complete / False to resume later
		 */
		public void setDownloaded(String path, boolean status) {
			ContentValues cv = new ContentValues();
			cv.put(COL_DOWNLOADED, status);
			neoDB.update(TABLE_NAME, cv, COL_PATH+"=?", new String[] {path});
		}
		
		/**
		 * Call this to set the Md5, just after creating an empty file.
		 * Note: Make sure not to call this before creating an empty file, 
		 * otherwise it might cause the subsequent call to return UPDATE_RESUME wrongly.
		 * 
		 * @param path	Path of the file
		 * @param md5 MD5 sum of the file
		 */
		public void setMd5(String path, String md5) {
			ContentValues cv = new ContentValues();
			cv.put(COL_MD5, md5);
			neoDB.update(TABLE_NAME, cv, COL_PATH+"=?", new String[] {path});
		}
		
		private String getMd5Sum(File file) {
			try {
				byte[] buffer = new byte[8192];
				FileInputStream iStream = new FileInputStream(file);
				MessageDigest md = MessageDigest.getInstance("MD5");
				DigestInputStream dis = new DigestInputStream(iStream, md);
				while(dis.read(buffer) != -1) { }
				byte[] data = md.digest();
				StringBuffer md5 = new StringBuffer();
				for (int i=0;i<data.length;i++) {
					String hex = Integer.toHexString(0xFF & data[i]);
					if(hex.length() == 1)
						md5.append("0");
				    md5.append(hex);
				}
				dis.close();
				return new String(md5);
			} catch(Exception e) { 
				if(enableDebug)
					e.printStackTrace();
			}
			return "";
		}
		
		/**
		 * 
		 * @param path
		 * @param md5
		 * @return
		 */
		public UPDATE_STATUS updateAndGetStatus(String path, String md5) {
			boolean latestFileAvailable = false;
			Cursor c = neoDB.query(TABLE_NAME, new String[] {COL_MD5, COL_DOWNLOADED}, 
					COL_PATH+"=?", new String[]{path}, null, null, null, "1");

			int iMd5 = c.getColumnIndex(COL_MD5);
			int iDownloaded = c.getColumnIndex(COL_DOWNLOADED);
			File file = new File(path);
			
			if(c != null && c.getCount() > 0) {
				c.moveToFirst();
				boolean downloaded = (c.getInt(iDownloaded) > 0);
				boolean md5Match = (md5.compareToIgnoreCase(c.getString(iMd5)) == 0);
				c.close();

				if(!md5Match || !file.exists()) {
					if(downloaded)
						setDownloaded(path, false);
					return UPDATE_STATUS.UPDATE_REQUIRED;
				} else {
					if(downloaded)
						return UPDATE_STATUS.UPDATE_COMPLETE;
					return UPDATE_STATUS.UPDATE_RESUME;
				}				
			} else if(file.exists()) {
				// File exists check its MD5
				if(getMd5Sum(file).equalsIgnoreCase(md5))
					latestFileAvailable = true;
			}
			
			// New path - insert this
			ContentValues cv = new ContentValues();
			cv.put(COL_PATH, path);
			if(latestFileAvailable) {
				// Latest file is available - but it is not present in the db
				cv.put(COL_MD5, md5);
				cv.put(COL_DOWNLOADED, true);
			} else {
				cv.put(COL_MD5, ""); // Make sure not to input correct md5 - otherwise it might cause
									 // the subsequent call to return UPDATE_RESUME wrongly
				cv.put(COL_DOWNLOADED, false);
			}
			neoDB.insert(TABLE_NAME, null, cv);

			return latestFileAvailable ? UPDATE_STATUS.UPDATE_COMPLETE : UPDATE_STATUS.UPDATE_REQUIRED;
		}

		@Override
		public void onCreate(SQLiteDatabase db) {
			db.execSQL("CREATE TABLE "+TABLE_NAME+" ("+_ID+
					" INTEGER PRIMARY KEY AUTOINCREMENT, "+COL_PATH+" TEXT NOT NULL, "+
					COL_MD5+" TEXT NOT NULL, "+COL_DOWNLOADED+" INTEGER);");
			db.execSQL("CREATE TABLE "+DEVICES_TABLE+" ("+_ID+
					" INTEGER PRIMARY KEY AUTOINCREMENT, "+COL_DEVICES+" TEXT NOT NULL);");
		}
		
		public void clearDevicesList() {
			neoDB.execSQL("DELETE FROM "+DEVICES_TABLE);
		}

		@Override
		public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
			db.execSQL("DROP TABLE IF EXISTS "+TABLE_NAME);
			db.execSQL("DROP TABLE IF EXISTS "+TABLE_NAME);
			onCreate(db);
		}
		
		@Override
		public void finalize() {
			neoDB.close();
		}
	}
	private static class NewAsset {
		public String path;
		public String md5;
	}
	private class DownloadRunnable implements Runnable {
		@Override
		public void run() {
			while(true) {
				NewAsset asset = null;
				lock.lock();
				try {
					if(filesToDownload.size() > 0)
						asset = filesToDownload.remove(0);
				} catch(Exception e) { 
					if(enableDebug)
						e.printStackTrace();
				}
				lock.unlock();
				if(asset != null)
					downloadFile(asset, null);
				else
					return;
			}
		}
	}
}
