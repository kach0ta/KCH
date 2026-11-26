package com.kach0ta.kch;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final String API = "https://kch-api.nigdog950.workers.dev";
    private static final int BG=Color.rgb(10,9,15), PANEL=Color.rgb(23,19,34);
    private static final int PURPLE=Color.rgb(166,104,255), ACID=Color.rgb(190,255,55), MUTED=Color.rgb(165,158,180);
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private SharedPreferences prefs;
    private LinearLayout root;
    private EditText username, password;
    private TextView status;

    @Override public void onCreate(Bundle b) {
        super.onCreate(b);
        prefs=getSharedPreferences("kch_session",MODE_PRIVATE);
        getWindow().setStatusBarColor(BG); getWindow().setNavigationBarColor(BG);
        if (prefs.getString("token",null)!=null) loadChats(); else showAuth();
    }

    private void base(String subtitle) {
        ScrollView scroll=new ScrollView(this); scroll.setFillViewport(true); scroll.setBackgroundColor(BG);
        root=new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL); root.setPadding(dp(22),dp(30),dp(22),dp(24));
        scroll.addView(root); setContentView(scroll);
        root.addView(label("K.C.H.",34,Color.WHITE,true));
        add(root,label("Kach0ta's Communication Hideout",14,MUTED,false),4);
        add(root,label(subtitle,11,ACID,true),28);
    }

    private void showAuth() {
        base("ЛИЧНЫЙ МЕССЕНДЖЕР");
        add(root,label("Твой уголок приватности.",23,Color.WHITE,true),8);
        add(root,label("Войди или создай аккаунт. Имя пользователя: 3–24 символа, пароль: минимум 6 символов.",13,MUTED,false),8);
        username=new EditText(this); username.setSingleLine(true); username.setHint("Имя пользователя"); username.setTextColor(Color.WHITE); username.setHintTextColor(MUTED); username.setBackgroundColor(PANEL); add(root,username,18);
        password=new EditText(this); password.setSingleLine(true); password.setHint("Пароль"); password.setInputType(129); password.setTextColor(Color.WHITE); password.setHintTextColor(MUTED); password.setBackgroundColor(PANEL); add(root,password,10);
        Button login=button("ВОЙТИ",PURPLE); add(root,login,18);
        Button register=button("СОЗДАТЬ АККАУНТ",ACID); add(root,register,10);
        status=label("",13,MUTED,false); add(root,status,14);
        login.setOnClickListener(v->authenticate(false)); register.setOnClickListener(v->authenticate(true));
        footer();
    }

    private void authenticate(boolean create) {
        String name=username.getText().toString().trim(), pass=password.getText().toString();
        if(name.isEmpty()||pass.isEmpty()){ showStatus("Заполни оба поля."); return; }
        if(pass.length()<6){ showStatus("Пароль должен содержать минимум 6 символов."); return; }
        hideKeyboard();
        JSONObject body=new JSONObject();
        try { body.put("username",name); body.put("password",pass); } catch(Exception ignored) {}
        showStatus("Подключаемся к серверу…");
        io.execute(()->{
            try {
                JSONObject result=request("POST",create?"/v1/auth/register":"/v1/auth/login",body,null);
                String token=result.getString("token");
                prefs.edit().putString("token",token).putString("username",name.toLowerCase()).apply();
                runOnUiThread(this::loadChats);
            } catch(Exception e){ runOnUiThread(()->showStatus(message(e))); }
        });
    }

    private void loadChats() {
        base("ТВОЁ ПРОСТРАНСТВО");
        add(root,label("Загрузка диалогов…",14,MUTED,false),12);
        io.execute(()->{
            try {
                JSONObject data=request("GET","/v1/conversations",null,prefs.getString("token",null));
                JSONArray chats=data.optJSONArray("conversations");
                runOnUiThread(()->renderChats(chats==null?new JSONArray():chats));
            } catch(Exception e) {
                runOnUiThread(()->{
                    if(message(e).contains("unauthorized")) { prefs.edit().remove("token").apply(); showAuth(); }
                    else { base("ОШИБКА СОЕДИНЕНИЯ"); add(root,label(message(e),14,MUTED,false),12); add(root,button("ПОВТОРИТЬ",PURPLE),16); ((Button)root.getChildAt(root.getChildCount()-1)).setOnClickListener(v->loadChats()); footer(); }
                });
            }
        });
    }

    private void renderChats(JSONArray chats) {
        base("ТВОЁ ПРОСТРАНСТВО");
        add(root,label("Привет, "+prefs.getString("username","")+".",20,Color.WHITE,true),8);
        add(root,label("Список чатов",12,PURPLE,true),20);
        if(chats.length()==0) add(root,label("Пока здесь пусто. Для начала нужен второй аккаунт и созданный диалог.",14,MUTED,false),10);
        for(int i=0;i<chats.length();i++){
            JSONObject c=chats.optJSONObject(i); if(c==null)continue;
            String kind=c.optString("kind","chat"), title=c.optString("title","");
            if(title.isEmpty()) title=kind.equals("direct")?"Личный чат":kind.equals("group")?"Группа":"Приватный канал";
            root.addView(card(title,kind+" · "+c.optString("role","member")));
        }
        Button refresh=button("ОБНОВИТЬ",PURPLE); add(root,refresh,20); refresh.setOnClickListener(v->loadChats());
        Button logout=button("ВЫЙТИ ИЗ АККАУНТА",PANEL); add(root,logout,10);
        logout.setOnClickListener(v->{prefs.edit().clear().apply();showAuth();});
        footer();
    }

    private JSONObject request(String method,String path,JSONObject body,String token) throws Exception {
        HttpURLConnection c=(HttpURLConnection)new URL(API+path).openConnection();
        c.setRequestMethod(method); c.setConnectTimeout(15000); c.setReadTimeout(15000);
        c.setRequestProperty("Accept","application/json");
        if(token!=null)c.setRequestProperty("Authorization","Bearer "+token);
        if(body!=null){c.setDoOutput(true);c.setRequestProperty("Content-Type","application/json; charset=utf-8");try(OutputStream o=c.getOutputStream()){o.write(body.toString().getBytes(StandardCharsets.UTF_8));}}
        int code=c.getResponseCode(); InputStream in=code>=200&&code<300?c.getInputStream():c.getErrorStream();
        StringBuilder text=new StringBuilder(); try(BufferedReader r=new BufferedReader(new InputStreamReader(in,StandardCharsets.UTF_8))){String line;while((line=r.readLine())!=null)text.append(line);}
        c.disconnect(); JSONObject out=new JSONObject(text.toString());
        if(code<200||code>=300)throw new Exception(out.optString("error","HTTP "+code));
        return out;
    }

    private void showStatus(String s){if(status!=null)status.setText(s);}
    private String message(Exception e){
        String m=e.getMessage();
        if(m==null)return "Не удалось связаться с сервером.";
        if(m.contains("username_taken"))return "Это имя пользователя уже занято.";
        if(m.contains("invalid_credentials"))return "Неверное имя пользователя или пароль.";
        if(m.contains("credentials_required"))return "Введи имя пользователя и пароль.";
        if(m.contains("invalid_registration_data")||m.contains("username must be"))return "Проверь данные: имя пользователя должно содержать 3–24 символа, пароль — 6–128 символов.";
        if(m.contains("could_not_create_account"))return "Не удалось создать аккаунт. Попробуй ещё раз.";
        if(m.contains("unauthorized"))return "Сессия завершилась. Войди снова.";
        String lower=m.toLowerCase();
        if(lower.contains("unable to resolve host")||lower.contains("failed to connect")||lower.contains("timeout")||lower.contains("network is unreachable"))return "Нет соединения с сервером. Проверь интернет.";
        return "Не удалось выполнить запрос. Попробуй ещё раз.";
    }
    private void hideKeyboard(){try{((InputMethodManager)getSystemService(Context.INPUT_METHOD_SERVICE)).hideSoftInputFromWindow(password.getWindowToken(),0);}catch(Exception ignored){}}
    private Button button(String s,int color){Button b=new Button(this);b.setText(s);b.setTextColor(color==ACID?BG:Color.WHITE);b.setTextSize(13);b.setAllCaps(false);b.setBackgroundColor(color);return b;}
    private View card(String title,String sub){LinearLayout box=new LinearLayout(this);box.setOrientation(1);box.setPadding(dp(15),dp(14),dp(15),dp(14));box.setBackgroundColor(PANEL);LinearLayout.LayoutParams p=params();p.topMargin=dp(9);box.setLayoutParams(p);box.addView(label(title,16,Color.WHITE,true));add(box,label(sub,11,MUTED,false),4);return box;}
    private void footer(){TextView f=label("K.C.H.  •  FOUNDATION BUILD",10,MUTED,false);f.setGravity(Gravity.CENTER);add(root,f,32);TextView c=label("kach0ta  ·  vo1dka  ·  r3z0n  ·  a1r1s",8,Color.rgb(83,78,94),false);c.setGravity(Gravity.CENTER);c.setAlpha(.55f);add(root,c,10);}
    private TextView label(String s,int size,int color,boolean bold){TextView t=new TextView(this);t.setText(s);t.setTextSize(size);t.setTextColor(color);if(bold)t.setTypeface(Typeface.DEFAULT,Typeface.BOLD);return t;}
    private void add(LinearLayout p,View v,int top){LinearLayout.LayoutParams lp=params();lp.topMargin=dp(top);p.addView(v,lp);}
    private LinearLayout.LayoutParams params(){return new LinearLayout.LayoutParams(-1,-2);}
    private int dp(int n){return (int)(n*getResources().getDisplayMetrics().density+.5f);}
    @Override protected void onDestroy(){super.onDestroy();io.shutdown();}
}
