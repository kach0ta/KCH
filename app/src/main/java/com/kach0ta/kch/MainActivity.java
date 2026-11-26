package com.kach0ta.kch;

import android.app.Activity;
import android.content.Intent;
import android.graphics.BitmapFactory;
import android.util.Base64;
import android.widget.ImageView;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final String API = "https://kch-api.de2.netrun.io";
    private static final int BG=Color.rgb(9,11,20), PANEL=Color.rgb(25,29,48);
    private static final int PANEL2=Color.rgb(34,39,64), PURPLE=Color.rgb(169,126,255);
    private static final int ACID=Color.rgb(194,255,92), CYAN=Color.rgb(130,211,255);
    private static final int WHITE=Color.rgb(245,246,255), MUTED=Color.rgb(166,174,198);
    private static final String TOKEN_AAD="kch.session.token.v1";
    private final ExecutorService io=Executors.newSingleThreadExecutor();
    private SharedPreferences prefs;
    private LinearLayout root, content;
    private EditText username,password;
    private TextView status;
    private JSONArray cachedChats=new JSONArray();
    private String selectedTab="chats";
    private static final int PICK_AVATAR=701;
    private JSONObject myProfile=new JSONObject();

    @Override public void onCreate(Bundle b) {
        super.onCreate(b);
        prefs=getSharedPreferences("kch_session",MODE_PRIVATE);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        getWindow().getDecorView().setSystemUiVisibility(0);
        String token=readEncryptedToken();
        if(token!=null) loadChats(); else showAuth();
    }

    private void base(String subtitle) {
        ScrollView scroll=new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BG);
        scroll.setClipToPadding(false);
        root=new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(18),dp(22),dp(18),dp(22));
        scroll.addView(root);
        setContentView(scroll);
        LinearLayout brand=new LinearLayout(this);
        brand.setOrientation(LinearLayout.VERTICAL);
        brand.setPadding(dp(18),dp(16),dp(18),dp(16));
        brand.setBackground(glass(0xCC252B48,0xAA342C5B,22));
        root.addView(brand,params());
        TextView logo=label("K.C.H.",30,WHITE,true);
        brand.addView(logo);
        TextView tagline=label("Kach0ta's Communication Hideout",12,MUTED,false);
        add(brand,tagline,2);
        TextView section=label(subtitle,10,ACID,true);
        section.setLetterSpacing(.12f);
        add(root,section,18);
    }

    private void showAuth() {
        base("PRIVATE MESSENGER  /  ВХОД");
        LinearLayout panel=panel();
        add(root,panel,8);
        add(panel,label("Связь без лишнего шума.",23,WHITE,true),2);
        add(panel,label("Войди или создай аккаунт K.C.H.",13,MUTED,false),7);
        username=field("Имя пользователя",false);
        add(panel,username,18);
        password=field("Пароль",true);
        add(panel,password,10);
        Button login=button("ВОЙТИ",PURPLE,WHITE);
        add(panel,login,16);
        Button register=button("СОЗДАТЬ АККАУНТ",ACID,BG);
        add(panel,register,9);
        status=label("",12,CYAN,false);
        add(panel,status,12);
        login.setOnClickListener(v->authenticate(false));
        register.setOnClickListener(v->authenticate(true));
        footer();
    }

    private void authenticate(boolean create) {
        String name=username.getText().toString().trim();
        String pass=password.getText().toString();
        String validation=validateCredentials(name,pass);
        if(validation!=null){showStatus(validation);return;}
        hideKeyboard();
        JSONObject body=new JSONObject();
        try{body.put("username",name);body.put("password",pass);}catch(Exception ignored){}
        showStatus("Подключаемся к серверу…");
        io.execute(()->{
            try{
                JSONObject result=request("POST",create?"/v1/auth/register":"/v1/auth/login",body,null);
                String token=result.getString("token");
                String encrypted=Aes256Gcm.encrypt(token,TOKEN_AAD.getBytes(StandardCharsets.UTF_8));
                prefs.edit().putString("token_enc",encrypted).remove("token").putString("username",name.toLowerCase()).apply();
                runOnUiThread(this::loadChats);
            }catch(Exception e){runOnUiThread(()->android.widget.Toast.makeText(this,message(e),android.widget.Toast.LENGTH_LONG).show());}
        });
    }

    private String readEncryptedToken() {
        String encrypted=prefs.getString("token_enc",null);
        if(encrypted!=null){
            try{return Aes256Gcm.decrypt(encrypted,TOKEN_AAD.getBytes(StandardCharsets.UTF_8));}
            catch(Exception e){prefs.edit().remove("token_enc").remove("token").apply();return null;}
        }
        // One-time migration of the old plaintext session token.
        String legacy=prefs.getString("token",null);
        if(legacy==null)return null;
        try{
            String sealed=Aes256Gcm.encrypt(legacy,TOKEN_AAD.getBytes(StandardCharsets.UTF_8));
            prefs.edit().putString("token_enc",sealed).remove("token").apply();
            return legacy;
        }catch(GeneralSecurityException e){
            prefs.edit().remove("token").apply();
            return null;
        }
    }

    private String sessionToken() {
        try{
            String value=prefs.getString("token_enc",null);
            return value==null?null:Aes256Gcm.decrypt(value,TOKEN_AAD.getBytes(StandardCharsets.UTF_8));
        }catch(Exception e){return null;}
    }

    private void loadChats() {
        base("ТВОЁ ПРОСТРАНСТВО");
        add(root,label("Загружаем твои диалоги…",14,MUTED,false),14);
        io.execute(()->{
            try{
                JSONObject data=request("GET","/v1/conversations",null,sessionToken());
                JSONArray chats=data.optJSONArray("conversations");
                runOnUiThread(()->{cachedChats=chats==null?new JSONArray():chats;renderHome();});
            }catch(Exception e){
                runOnUiThread(()->{
                    if(message(e).contains("unauthorized")){prefs.edit().clear().apply();showAuth();}
                    else{
                        base("НЕТ СОЕДИНЕНИЯ");
                        LinearLayout panel=panel();add(root,panel,8);
                        add(panel,label("Не удалось загрузить чаты",19,WHITE,true),2);
                        add(panel,label(message(e),13,MUTED,false),8);
                        Button retry=button("ПОВТОРИТЬ",PURPLE,WHITE);add(panel,retry,14);retry.setOnClickListener(v->loadChats());
                        footer();
                    }
                });
            }
        });
    }

    private void renderHome() {
        base("ТВОЁ ПРОСТРАНСТВО");
        LinearLayout top=new LinearLayout(this);
        top.setGravity(Gravity.CENTER_VERTICAL);
        top.setOrientation(LinearLayout.HORIZONTAL);
        TextView greeting=label("Привет, "+prefs.getString("username","")+".",20,WHITE,true);
        top.addView(greeting,new LinearLayout.LayoutParams(0,-2,1));
        TextView online=label("● ONLINE",10,ACID,true);
        top.addView(online);
        add(root,top,8);
        EditText search=field("Поиск по чатам",false);
        search.setFocusable(false);
        search.setOnClickListener(v->showStatus("Поиск подключим вместе с экраном чатов."));
        add(root,search,16);

        LinearLayout tabs=new LinearLayout(this);
        tabs.setOrientation(LinearLayout.HORIZONTAL);
        tabs.setPadding(dp(3),dp(3),dp(3),dp(3));
        tabs.setBackground(glass(0x6620243A,0x66292B49,24));
        add(root,tabs,14);
        addTab(tabs,"Чаты","chats");
        addTab(tabs,"Избранное","favorites");
        addTab(tabs,"Каналы","channels");

        content=new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        add(root,content,16);
        renderTabContent();
        LinearLayout bottom=new LinearLayout(this);
        bottom.setGravity(Gravity.CENTER);
        bottom.setPadding(dp(8),dp(10),dp(8),dp(10));
        bottom.setBackground(glass(0xDD242942,0xCC302B52,22));
        add(root,bottom,22);
        Button account=button("◉  МОЙ ПРОФИЛЬ",PANEL2,WHITE);
        bottom.addView(account,new LinearLayout.LayoutParams(0,dp(48),1));
        account.setOnClickListener(v->{ io.execute(()->{try{myProfile=request("GET","/v1/me",null,sessionToken());}catch(Exception ignored){} runOnUiThread(this::showAccount);}); });
        Button settings=button("⚙  НАСТРОЙКИ",PANEL2,WHITE);
        LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(0,dp(48),1);
        lp.leftMargin=dp(8);bottom.addView(settings,lp);
        settings.setOnClickListener(v->showSettings());
        footer();
    }

    private void addTab(LinearLayout row,String title,String key) {
        Button b=button(title,selectedTab.equals(key)?0xAA69549A:Color.TRANSPARENT,selectedTab.equals(key)?WHITE:MUTED);
        b.setBackground(glass(selectedTab.equals(key)?0xAA69549A:0x0020243A,selectedTab.equals(key)?0xAA51447E:0x0020243A,22));
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(0,dp(42),1);
        p.setMargins(dp(2),0,dp(2),0);row.addView(b,p);
        b.setOnClickListener(v->{selectedTab=key;renderHome();});
    }

    private void renderTabContent() {
        content.removeAllViews();
        if("chats".equals(selectedTab)){
            add(content,label("ПОСЛЕДНИЕ ДИАЛОГИ",10,MUTED,true),0);
            add(content,label("Удерживай чат, чтобы закрепить его вверху списка.",10,MUTED,false),4);
            if(cachedChats.length()==0){emptyState("Пока тихо","Создай диалог, и он появится здесь.");return;}
            ArrayList<JSONObject> ordered=new ArrayList<>();
            for(int i=0;i<cachedChats.length();i++){JSONObject c=cachedChats.optJSONObject(i);if(c!=null)ordered.add(c);}
            Set<String> pinned=prefs.getStringSet("pinned_chats",new HashSet<>());
            Collections.sort(ordered,(a,b)->Boolean.compare(pinned.contains(b.optString("id")),pinned.contains(a.optString("id"))));
            for(JSONObject c:ordered){
                String kind=c.optString("kind","chat");
                String title=c.optString("title","");
                if(title.isEmpty())title=kind.equals("direct")?"Личный чат":kind.equals("group")?"Группа":"Приватный канал";
                addChatCard(c.optString("id"),title,kind.equals("direct")?"ЛИЧНЫЙ ДИАЛОГ":kind.equals("group")?"ГРУППА":"КАНАЛ",c.optString("role","member"));
            }
        }else if("favorites".equals(selectedTab)){
            emptyState("Избранное","Твои заметки и сообщения самому себе.");
            Button self=button("ОТКРЫТЬ МОЙ ЧАТ",PURPLE,WHITE);add(content,self,10);
            self.setOnClickListener(v->openSelfChat());
        }else{
            emptyState("Каналы","Твои приватные каналы будут здесь.");
        }
    }

    private void addChatCard(String id,String title,String kind,String role) {
        LinearLayout card=panel();
        card.setOrientation(LinearLayout.HORIZONTAL);
        card.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams p=params();p.topMargin=dp(9);content.addView(card,p);
        TextView avatar=label(initials(title),18,WHITE,true);
        avatar.setGravity(Gravity.CENTER);
        avatar.setBackground(glass(0xCC604E91,0xCC32718B,50));
        LinearLayout.LayoutParams ap=new LinearLayout.LayoutParams(dp(48),dp(48));
        card.addView(avatar,ap);
        LinearLayout details=new LinearLayout(this);details.setOrientation(1);
        LinearLayout.LayoutParams dp=new LinearLayout.LayoutParams(0,-2,1);
        dp.leftMargin=dp(12);card.addView(details,dp);
        details.addView(label(title,15,WHITE,true));
        add(details,label(kind+"  ·  "+role,10,MUTED,false),4);
        TextView arrow=label(prefs.getStringSet("pinned_chats",new HashSet<>()).contains(id)?"⌖":"›",22,CYAN,false);card.addView(arrow);
        card.setOnLongClickListener(v->{Set<String> saved=new HashSet<>(prefs.getStringSet("pinned_chats",new HashSet<>()));if(saved.contains(id))saved.remove(id);else saved.add(id);prefs.edit().putStringSet("pinned_chats",saved).apply();renderHome();return true;});
    }

    private void emptyState(String title,String subtitle) {
        LinearLayout empty=panel();empty.setGravity(Gravity.CENTER);empty.setPadding(dp(20),dp(28),dp(20),dp(28));
        add(content,empty,8);
        TextView orb=label("✦",30,CYAN,true);orb.setGravity(Gravity.CENTER);
        empty.addView(orb);
        add(empty,label(title,18,WHITE,true),10);
        add(empty,label(subtitle,12,MUTED,false),5);
    }

    private void showSelfChat(String id) {
        base("ИЗБРАННОЕ");
        LinearLayout card=panel();add(root,card,8);
        add(card,label("Твои заметки",22,WHITE,true),2);
        add(card,label("Личный чат с самим собой. Здесь можно будет хранить ссылки, заметки и сообщения.",13,MUTED,false),8);
        add(card,label("Чат создан. Отправка сообщений появится после подключения защищённого обмена.",12,CYAN,false),14);
        Button back=button("НАЗАД К ЧАТАМ",PURPLE,WHITE);add(card,back,18);back.setOnClickListener(v->loadChats());
        footer();
    }

    private void showSettings() {
        base("НАСТРОЙКИ");
        LinearLayout panel=panel();add(root,panel,8);
        add(panel,label("Внешний вид",18,WHITE,true),2);
        add(panel,label("Тёмная тема K.C.H. с мягкими стеклянными элементами.",13,MUTED,false),8);
        add(panel,label("Уведомления и приватность появятся здесь по мере подключения функций.",12,MUTED,false),14);

        add(panel,label("КРИПТОГРАФИЯ УСТРОЙСТВА",10,ACID,true),14);
        add(panel,label("Локальная проверка Android Keystore. Никакие ключи не отправляются на сервер.",11,MUTED,false),5);
        Button identityCheck=button("ПРОВЕРИТЬ КЛЮЧ УСТРОЙСТВА",PANEL2,WHITE);
        add(panel,identityCheck,10);
        TextView identityStatus=label("Проверка ещё не запускалась.",11,MUTED,false);
        add(panel,identityStatus,8);
        identityCheck.setOnClickListener(v->{
            identityCheck.setEnabled(false);
            identityStatus.setText("Проверяем Android Keystore…");
            io.execute(()->{
                String result;
                try{
                    byte[] publicKey=DeviceIdentity.getOrCreatePublicKey();
                    byte[] reloadedPublicKey=DeviceIdentity.getOrCreatePublicKey();
                    if(!java.security.MessageDigest.isEqual(publicKey,reloadedPublicKey))
                        throw new GeneralSecurityException("Device identity changed between reads");

                    byte[] challenge="KCH-DEVICE-IDENTITY-SELF-TEST-V1".getBytes(StandardCharsets.UTF_8);
                    byte[] signature=DeviceIdentity.sign("SELF-TEST",challenge);
                    boolean valid=DeviceIdentity.verify(publicKey,"SELF-TEST",challenge,signature);

                    byte[] alteredChallenge=challenge.clone();
                    alteredChallenge[alteredChallenge.length-1]^=1;
                    boolean alteredAccepted=DeviceIdentity.verify(
                            publicKey,"SELF-TEST",alteredChallenge,signature);

                    if(!valid||alteredAccepted)
                        throw new GeneralSecurityException("Signature self-test failed");
                    result="УСПЕШНО: ключ создан и повторно прочитан; подпись создана и проверена; подпись для изменённых данных отклонена. Отпечаток SHA-256: "+DeviceIdentity.fingerprint(publicKey);
                }catch(Exception e){
                    result="ОШИБКА ПРОВЕРКИ: "+message(e);
                }
                final String report=result;
                runOnUiThread(()->{
                    identityStatus.setText(report);
                    identityCheck.setEnabled(true);
                });
            });
        });

        Button prekeyCheck=button("ПРОВЕРИТЬ ПОДПИСЬ PREKEY",PANEL2,WHITE);
        add(panel,prekeyCheck,8);
        TextView prekeyStatus=label("Проверка предварительного ключа ещё не запускалась.",11,MUTED,false);
        add(panel,prekeyStatus,8);
        prekeyCheck.setOnClickListener(v->{
            prekeyCheck.setEnabled(false);
            prekeyStatus.setText("Проверяем подпись предварительного ключа…");
            io.execute(()->{
                String report;
                try{
                    byte[] trustedIdentity=DeviceIdentity.getOrCreatePublicKey();
                    java.security.KeyPair prekey=CryptoPrimitives.newEphemeralKeyPair();
                    long now=System.currentTimeMillis()/1000L;
                    SignedPreKeyBundle bundle=SignedPreKeyBundle.create(
                            "local-account","local-device","spk-self-test-1",
                            now+3600L,prekey.getPublic());
                    boolean valid=bundle.verify(trustedIdentity,now);

                    byte[] changedTranscript=SignedPreKeyBundle.canonicalPayload(
                            bundle.accountId,bundle.deviceId,"spk-substituted",
                            bundle.expiresAtEpochSeconds,bundle.getPublicKeyEncoded());
                    boolean changedAccepted=DeviceIdentity.verify(
                            trustedIdentity,"SIGNED-PREKEY-V1",
                            changedTranscript,bundle.getSignature());

                    java.security.KeyPair attacker=CryptoPrimitives.newEphemeralKeyPair();
                    byte[] attackerIdentity=CryptoPrimitives.encodePublicKey(attacker.getPublic());
                    boolean wrongIdentityAccepted=bundle.verify(attackerIdentity,now);
                    boolean expiredAccepted=bundle.verify(trustedIdentity,now+7200L);

                    if(!valid||changedAccepted||wrongIdentityAccepted||expiredAccepted)
                        throw new GeneralSecurityException("Signed prekey self-test failed");
                    report="УСПЕШНО: подпись верна; подмена ID ключа отклонена; чужая identity отклонена; просроченный bundle отклонён.";
                }catch(Exception e){
                    report="ОШИБКА ПРОВЕРКИ PREKEY: "+message(e);
                }
                final String result=report;
                runOnUiThread(()->{
                    prekeyStatus.setText(result);
                    prekeyCheck.setEnabled(true);
                });
            });
        });

        Button storageCheck=button("ПРОВЕРИТЬ ХРАНЕНИЕ PREKEY",PANEL2,WHITE);
        add(panel,storageCheck,8);
        TextView storageStatus=label("Проверка локального хранения ещё не запускалась.",11,MUTED,false);
        add(panel,storageStatus,8);
        storageCheck.setOnClickListener(v->{
            storageCheck.setEnabled(false);
            storageStatus.setText("Проверяем зашифрованное хранилище…");
            io.execute(()->{
                String report;
                try{
                    long expiry=4102444800L;
                    LocalPreKeyStore.StoredPreKey first=LocalPreKeyStore.getOrCreate(
                            this,"local-account","local-device",
                            "settings-self-test-v1",expiry);
                    LocalPreKeyStore.StoredPreKey second=LocalPreKeyStore.getOrCreate(
                            this,"local-account","local-device",
                            "settings-self-test-v1",expiry);
                    byte[] firstPublic=CryptoPrimitives.encodePublicKey(first.keyPair.getPublic());
                    byte[] secondPublic=CryptoPrimitives.encodePublicKey(second.keyPair.getPublic());
                    byte[] firstPrivate=first.keyPair.getPrivate().getEncoded();
                    byte[] secondPrivate=second.keyPair.getPrivate().getEncoded();
                    boolean samePublic=java.security.MessageDigest.isEqual(firstPublic,secondPublic);
                    boolean samePrivate=java.security.MessageDigest.isEqual(firstPrivate,secondPrivate);
                    boolean signed=second.bundle.verify(DeviceIdentity.getOrCreatePublicKey(),
                            System.currentTimeMillis()/1000L);
                    if(!samePublic||!samePrivate||!signed)
                        throw new GeneralSecurityException("Local prekey persistence check failed");
                    report="УСПЕШНО: приватный ключ восстановлен после повторного чтения; публичный ключ совпадает; подпись identity действительна. Приватный ключ хранится в зашифрованном виде локально.";
                }catch(Exception e){
                    report="ОШИБКА ХРАНЕНИЯ PREKEY: "+message(e);
                }
                final String result=report;
                runOnUiThread(()->{
                    storageStatus.setText(result);
                    storageCheck.setEnabled(true);
                });
            });
        });

        Button oneTimeCheck=button("ПРОВЕРИТЬ ОДНОРАЗОВЫЕ PREKEY",PANEL2,WHITE);
        add(panel,oneTimeCheck,8);
        TextView oneTimeStatus=label("Пул одноразовых ключей ещё не проверялся.",11,MUTED,false);
        add(panel,oneTimeStatus,8);
        oneTimeCheck.setOnClickListener(v->{
            oneTimeCheck.setEnabled(false);
            oneTimeStatus.setText("Создаём и повторно загружаем одноразовый ключ…");
            io.execute(()->{
                String report;
                try{
                    String keyId="settings-otpk-self-test-v1";
                    LocalOneTimePreKeyStore.StoredOneTimePreKey first=
                            LocalOneTimePreKeyStore.getOrCreate(
                                    this,"local-account","local-device",keyId);
                    LocalOneTimePreKeyStore.StoredOneTimePreKey second=
                            LocalOneTimePreKeyStore.load(
                                    this,"local-account","local-device",keyId);
                    byte[] firstPublic=first.publicKeyEncoded;
                    byte[] secondPublic=second.publicKeyEncoded;
                    byte[] firstPrivate=first.keyPair.getPrivate().getEncoded();
                    byte[] secondPrivate=second.keyPair.getPrivate().getEncoded();
                    boolean samePublic=java.security.MessageDigest.isEqual(firstPublic,secondPublic);
                    boolean samePrivate=java.security.MessageDigest.isEqual(firstPrivate,secondPrivate);
                    byte[] transcript=OneTimePreKeyBundle.canonicalPayload(
                            second.accountId,second.deviceId,second.keyId,second.publicKeyEncoded);
                    boolean signed=DeviceIdentity.verify(DeviceIdentity.getOrCreatePublicKey(),
                            "ONE-TIME-PREKEY-V1",transcript,second.signature);
                    java.security.KeyPair other=CryptoPrimitives.newEphemeralKeyPair();
                    byte[] otherIdentity=CryptoPrimitives.encodePublicKey(other.getPublic());
                    boolean foreignAccepted=DeviceIdentity.verify(otherIdentity,
                            "ONE-TIME-PREKEY-V1",transcript,second.signature);
                    if(!samePublic||!samePrivate||!signed||foreignAccepted)
                        throw new GeneralSecurityException("One-time prekey self-test failed");
                    report="УСПЕШНО: одноразовый ключ сохранён и восстановлен; публичная и приватная части совпали; подпись identity действительна; чужая identity отклонена. Статус: "+second.status+". Ключ остаётся только на устройстве.";
                }catch(Exception e){
                    report="ОШИБКА ОДНОРАЗОВОГО PREKEY: "+message(e);
                }
                final String result=report;
                runOnUiThread(()->{
                    oneTimeStatus.setText(result);
                    oneTimeCheck.setEnabled(true);
                });
            });
        });

        Button back=button("НАЗАД К ЧАТАМ",PURPLE,WHITE);add(panel,back,18);back.setOnClickListener(v->renderHome());
        footer();
    }


    private void showAccount() {
        base("МОЙ ПРОФИЛЬ");
        LinearLayout card=panel();add(root,card,8);
        ImageView avatar=new ImageView(this);
        avatar.setScaleType(ImageView.ScaleType.CENTER_CROP);
        avatar.setBackground(glass(0xCC604E91,0xCC32718B,60));
        avatar.setClipToOutline(true);
        LinearLayout.LayoutParams avp=new LinearLayout.LayoutParams(dp(104),dp(104));
        avp.gravity=Gravity.CENTER;card.addView(avatar,avp);
        String encoded=myProfile.optString("avatar","");
        if(!encoded.isEmpty()){
            try{byte[] bytes=Base64.decode(encoded,Base64.DEFAULT);avatar.setImageBitmap(BitmapFactory.decodeByteArray(bytes,0,bytes.length));}
            catch(Exception ignored){}
        }
        Button change=button("ИЗМЕНИТЬ ФОТО",PANEL2,WHITE);add(card,change,12);
        change.setOnClickListener(v->pickAvatar());
        add(card,label("Ник",12,MUTED,true),18);
        EditText nick=field("Ник",false);nick.setText(prefs.getString("username",""));add(card,nick,6);
        add(card,label("Отображаемое имя",12,MUTED,true),12);
        EditText display=field("Как тебя видят другие",false);display.setText(myProfile.optString("displayName",prefs.getString("username","")));add(card,display,6);
        Button save=button("СОХРАНИТЬ ИЗМЕНЕНИЯ",PURPLE,WHITE);add(card,save,16);
        TextView info=label("Фото до 5 МБ. Ник: английские буквы, цифры и подчёркивание.",11,MUTED,false);add(card,info,10);
        save.setOnClickListener(v->{
            String n=nick.getText().toString().trim();
            if(n.length()<4||n.length()>24||!n.matches("[A-Za-z0-9_]+")){info.setText("Проверь ник: от 4 до 24 символов, только A–Z, 0–9 и _.");return;}
            JSONObject body=new JSONObject();
            try{body.put("username",n);body.put("displayName",display.getText().toString().trim());}catch(Exception ignored){}
            saveProfile(body,info);
        });
        Button back=button("НАЗАД К ЧАТАМ",PANEL2,WHITE);add(card,back,10);back.setOnClickListener(v->renderHome());
        footer();
    }

    private void pickAvatar() {
        Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);i.setType("image/*");i.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(i,PICK_AVATAR);
    }

    @Override protected void onActivityResult(int requestCode,int resultCode,Intent data) {
        super.onActivityResult(requestCode,resultCode,data);
        if(requestCode==PICK_AVATAR&&resultCode==RESULT_OK&&data!=null&&data.getData()!=null){
            io.execute(()->{
                try(InputStream in=getContentResolver().openInputStream(data.getData())){
                    byte[] bytes=readLimited(in,5*1024*1024);
                    String b64=Base64.encodeToString(bytes,Base64.NO_WRAP);
                    JSONObject body=new JSONObject();body.put("avatar",b64);
                    JSONObject updated=request("POST","/v1/me/profile",body,sessionToken());myProfile=updated;
                    runOnUiThread(this::showAccount);
                }catch(Exception e){runOnUiThread(()->android.widget.Toast.makeText(this,message(e),android.widget.Toast.LENGTH_LONG).show());}
            });
        }
    }

    private byte[] readLimited(InputStream in,int max)throws Exception {
        java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream();byte[] b=new byte[8192];int n,total=0;
        while((n=in.read(b))!=-1){total+=n;if(total>max)throw new Exception("avatar_too_large");out.write(b,0,n);}
        return out.toByteArray();
    }

    private void saveProfile(JSONObject body,TextView info) {
        io.execute(()->{try{
            JSONObject updated=request("POST","/v1/me/profile",body,sessionToken());myProfile=updated;
            String name=updated.optString("username",prefs.getString("username",""));
            prefs.edit().putString("username",name).apply();
            runOnUiThread(()->{info.setText("Профиль сохранён.");});
        }catch(Exception e){runOnUiThread(()->info.setText(message(e)));}});
    }

    private void openSelfChat() {
        showStatus("Открываем личное пространство…");
        io.execute(()->{try{
            JSONObject body=new JSONObject();body.put("kind","direct");body.put("self",true);
            JSONObject result=request("POST","/v1/conversations",body,sessionToken());
            runOnUiThread(()->showSelfChat(result.optString("id")));
        }catch(Exception e){runOnUiThread(()->showStatus(message(e)));}});
    }

    private JSONObject request(String method,String path,JSONObject body,String token)throws Exception {
        HttpURLConnection c=(HttpURLConnection)new URL(API+path).openConnection();
        c.setRequestMethod(method);c.setConnectTimeout(12000);c.setReadTimeout(12000);
        c.setRequestProperty("Accept","application/json");
        if(token!=null)c.setRequestProperty("Authorization","Bearer "+token);
        if(body!=null){c.setDoOutput(true);c.setRequestProperty("Content-Type","application/json; charset=utf-8");try(OutputStream o=c.getOutputStream()){o.write(body.toString().getBytes(StandardCharsets.UTF_8));}}
        int code=c.getResponseCode();InputStream in=code>=200&&code<300?c.getInputStream():c.getErrorStream();
        StringBuilder text=new StringBuilder();
        try(BufferedReader r=new BufferedReader(new InputStreamReader(in,StandardCharsets.UTF_8))){String line;while((line=r.readLine())!=null)text.append(line);}
        c.disconnect();JSONObject out=new JSONObject(text.toString());
        if(code<200||code>=300)throw new Exception(out.optString("error","HTTP "+code));
        return out;
    }

    private String validateCredentials(String n,String p){
        if(n.isEmpty())return "Введи ник.";
        if(n.length()<4)return "Ник слишком короткий. Нужно минимум 4 символа.";
        if(n.length()>24)return "Ник слишком длинный. Максимум 24 символа.";
        if(!n.matches("[A-Za-z0-9_]+"))return "В нике разрешены только английские буквы, цифры и _.";
        if(p.isEmpty())return "Введи пароль.";
        if(p.length()<6)return "Пароль слишком короткий. Нужно минимум 6 символов.";
        if(p.length()>8)return "Пароль слишком длинный. Максимум 8 символов.";
        if(!p.matches("[A-Za-z0-9_]+"))return "В пароле разрешены только английские буквы, цифры и _.";
        return null;
    }

    private String message(Exception e){
        String m=e.getMessage();if(m==null)return "Не удалось связаться с сервером.";
        if(m.contains("username_taken"))return "Этот ник уже занят.";
        if(m.contains("avatar_too_large"))return "Фото больше 5 МБ. Выбери файл поменьше.";
        if(m.contains("invalid_credentials"))return "Неверный ник или пароль.";
        if(m.contains("unauthorized"))return "Сессия завершилась. Войди снова.";
        if(m.contains("timeout")||m.contains("failed to connect")||m.contains("Unable to resolve host"))return "Нет соединения с сервером. Проверь интернет.";
        if(m.contains("username_too_short"))return "Ник слишком короткий.";
        if(m.contains("username_too_long"))return "Ник слишком длинный.";
        if(m.contains("username_invalid_characters"))return "В нике разрешены только английские буквы, цифры и _.";
        if(m.contains("password_too_short"))return "Пароль слишком короткий.";
        if(m.contains("password_too_long"))return "Пароль слишком длинный.";
        if(m.contains("password_invalid_characters"))return "В пароле разрешены только английские буквы, цифры и _.";
        if(m.contains("server_error"))return "Ошибка на сервере. Попробуй позже.";
        return "Не удалось выполнить запрос: "+m;
    }

    private LinearLayout panel(){
        LinearLayout p=new LinearLayout(this);p.setOrientation(LinearLayout.VERTICAL);
        p.setPadding(dp(16),dp(16),dp(16),dp(16));
        p.setBackground(glass(0xD9272D49,0xCC292744,22));
        return p;
    }
    private EditText field(String hint,boolean secret){
        EditText e=new EditText(this);e.setSingleLine(true);e.setHint(hint);
        e.setTextColor(WHITE);e.setHintTextColor(MUTED);e.setTextSize(14);
        e.setPadding(dp(15),dp(11),dp(15),dp(11));
        e.setBackground(glass(0xCC171B2C,0xCC252A43,16));
        if(secret)e.setInputType(129);
        return e;
    }
    private Button button(String text,int color,int textColor){
        Button b=new Button(this);b.setText(text);b.setTextColor(textColor);b.setTextSize(12);
        b.setTypeface(Typeface.DEFAULT,Typeface.BOLD);b.setAllCaps(false);
        b.setPadding(dp(12),0,dp(12),0);b.setMinHeight(dp(46));b.setBackground(glass(color,color,18));
        return b;
    }
    private GradientDrawable glass(int top,int bottom,int radius){
        GradientDrawable d=new GradientDrawable(GradientDrawable.Orientation.TL_BR,new int[]{top,bottom});
        d.setCornerRadius(dp(radius));
        if((top>>>24)!=0)d.setStroke(dp(1),0x227E9CCB);
        return d;
    }
    private String initials(String s){if(s==null||s.isEmpty())return "K";return s.substring(0,1).toUpperCase();}
    private TextView label(String s,int size,int color,boolean bold){
        TextView t=new TextView(this);t.setText(s);t.setTextSize(size);t.setTextColor(color);
        if(bold)t.setTypeface(Typeface.DEFAULT,Typeface.BOLD);return t;
    }
    private void add(LinearLayout p,View v,int top){
        LinearLayout.LayoutParams lp=params();lp.topMargin=dp(top);p.addView(v,lp);
    }
    private LinearLayout.LayoutParams params(){return new LinearLayout.LayoutParams(-1,-2);}
    private int dp(int n){return (int)(n*getResources().getDisplayMetrics().density+.5f);}
    private void showStatus(String s){if(status!=null)status.setText(s);}
    private void hideKeyboard(){
        try{((InputMethodManager)getSystemService(Context.INPUT_METHOD_SERVICE)).hideSoftInputFromWindow(password.getWindowToken(),0);}
        catch(Exception ignored){}
    }
    private void footer(){
        TextView f=label("K.C.H.  •  FOUNDATION BUILD",9,MUTED,false);f.setGravity(Gravity.CENTER);add(root,f,26);
        TextView c=label("kach0ta  ·  vo1dka  ·  r3z0n  ·  a1r1s",8,Color.rgb(102,105,130),false);
        c.setGravity(Gravity.CENTER);c.setAlpha(.65f);add(root,c,8);
    }
    @Override protected void onDestroy(){super.onDestroy();io.shutdown();}
}
