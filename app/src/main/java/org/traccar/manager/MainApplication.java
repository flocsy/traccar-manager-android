/*
 * Copyright 2015 - 2016 Anton Tananaev (anton.tananaev@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.manager;

import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.support.multidex.MultiDexApplication;
import android.widget.Toast;

import org.traccar.manager.model.User;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.Cookie;
import okhttp3.JavaNetCookieJar;
import okhttp3.OkHttpClient;
import retrofit2.Call;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

public class MainApplication extends MultiDexApplication {

    public static final String PREFERENCE_AUTHENTICATED = "authenticated";
    public static final String PREFERENCE_URL = "url";
    public static final String PREFERENCE_EMAIL = "email";
    public static final String PREFERENCE_IGNORE_SSL_ERRORS="ignoreSslErrors";
    public static final String PREFERENCE_PERSISTENT_COOKIE="persistentCookie";
    public static final String PERSISTENT_COOKIE_NAME="tcrm";

    private static final String DEFAULT_SERVER = "http://demo.traccar.org"; // local - http://10.0.2.2:8082

    public interface GetServiceCallback {
        void onServiceReady(OkHttpClient client, Retrofit retrofit, CookieManager cookieManager, WebService service);
        boolean onFailure();
    }

    private SharedPreferences preferences;

    private OkHttpClient client;
    private WebService service;
    private Retrofit retrofit;
    private CookieManager cookieManager;
    private User user;

    private final List<GetServiceCallback> callbacks = new LinkedList<>();

    public void getServiceAsync(GetServiceCallback callback) {
        if (service != null) {
            callback.onServiceReady(client, retrofit, cookieManager, service);
        } else {
            if (callbacks.isEmpty()) {
                initService();
            }
            callbacks.add(callback);
        }
    }

    public void getServiceAsync(HttpCookie persistentLoginCookie,GetServiceCallback callback){
        if (service != null) {
            callback.onServiceReady(client, retrofit, cookieManager, service);
        } else {
            if (callbacks.isEmpty()) {
                initService(persistentLoginCookie);
            }
            callbacks.add(callback);
        }
    }

    public void getServiceAsync(String email, String password, boolean rememberField,GetServiceCallback callback){
        if (service != null) {
            callback.onServiceReady(client, retrofit, cookieManager, service);
        } else {
            if (callbacks.isEmpty()) {
                initService(email,password,rememberField);
            }
            callbacks.add(callback);
        }
    }

    public WebService getService() { return service; }
    public User getUser() { return user; }

    public void removeService() {
        service = null;
        user = null;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        preferences = PreferenceManager.getDefaultSharedPreferences(this);

        if (!preferences.contains(PREFERENCE_URL)) {
            preferences.edit().putString(PREFERENCE_URL, DEFAULT_SERVER).apply();
        }
    }

    private OkHttpClient.Builder getHttpClientBuilder(boolean ignoreSslErrors) {
        if(!ignoreSslErrors){
            return new OkHttpClient.Builder();
        }

        final TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                }

                @Override
                public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                }

                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return new java.security.cert.X509Certificate[]{
                    };
                }
            }
        };

        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        }
        catch (Exception exception){
            throw new RuntimeException(exception);
        }

        final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0]);
        builder.hostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
        return builder;
    }

    private WebService createService() {
        final String url = preferences.getString(PREFERENCE_URL, null);
        final boolean ignoreSslErrors = preferences.getBoolean(PREFERENCE_IGNORE_SSL_ERRORS, false);

        cookieManager = new CookieManager();
        cookieManager.setCookiePolicy(CookiePolicy.ACCEPT_ALL);

        client = getHttpClientBuilder(ignoreSslErrors)
                .readTimeout(0, TimeUnit.MILLISECONDS)
                .cookieJar(new JavaNetCookieJar(cookieManager)).build();

        try {
            retrofit = new Retrofit.Builder()
                    .client(client)
                    .baseUrl(url)
                    .addConverterFactory(JacksonConverterFactory.create())
                    .build();
        } catch (IllegalArgumentException e) {
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
            for (GetServiceCallback callback : callbacks) {
                callback.onFailure();
            }
            callbacks.clear();
        }

        return retrofit.create(WebService.class);
    }

    private void initService(){
        initService(null);
    }

    private void initService(String email, String password, boolean rememberField) {
        final WebService service = createService();
        service.addSession(email, password,rememberField).enqueue(new WebServiceCallback<User>(this) {
            @Override
            public void onSuccess(Response<User> response) {
                MainApplication.this.service = service;
                MainApplication.this.user = response.body();
                for (GetServiceCallback callback : callbacks) {
                    callback.onServiceReady(client, retrofit, cookieManager, service);
                }
                callbacks.clear();
            }

            @Override
            public void onFailure(Call<User> call, Throwable t) {
                boolean handled = false;
                for (GetServiceCallback callback : callbacks) {
                    handled = callback.onFailure();
                }
                callbacks.clear();
                if (!handled) {
                    super.onFailure(call, t);
                }
            }
        });
    }

    private void initService(HttpCookie persistentLoginCookie) {
        final WebService service = createService();
        if(persistentLoginCookie != null) {
            cookieManager.getCookieStore().add(retrofit.baseUrl().uri(), persistentLoginCookie);
        }

        service.getSession().enqueue(new WebServiceCallback<User>(this) {
            @Override
            public void onSuccess(Response<User> response) {
                MainApplication.this.service = service;
                MainApplication.this.user = response.body();
                for (GetServiceCallback callback : callbacks) {
                    callback.onServiceReady(client, retrofit, cookieManager, service);
                }
                callbacks.clear();
            }

            @Override
            public void onFailure(Call<User> call, Throwable t) {
                boolean handled = false;
                for (GetServiceCallback callback : callbacks) {
                    handled = callback.onFailure();
                }
                callbacks.clear();
                if (!handled) {
                    super.onFailure(call, t);
                }
            }
        });
    }

}
