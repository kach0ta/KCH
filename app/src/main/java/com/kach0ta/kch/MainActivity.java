package com.kach0ta.kch;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public final class MainActivity extends Activity {
    private static final int BG = Color.rgb(10, 9, 15);
    private static final int PANEL = Color.rgb(23, 19, 34);
    private static final int PURPLE = Color.rgb(166, 104, 255);
    private static final int ACID = Color.rgb(190, 255, 55);
    private static final int MUTED = Color.rgb(165, 158, 180);

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BG);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(22), dp(34), dp(22), dp(28));
        scroll.addView(root);

        root.addView(label("K.C.H.", 34, Color.WHITE, true));
        add(root, label("Kach0ta's Communication Hideout", 14, MUTED, false), 5);
        add(root, label("ЛИЧНЫЙ МЕССЕНДЖЕР // РАННЯЯ СБОРКА", 11, ACID, true), 34);
        add(root, label("Твой уголок приватности.", 23, Color.WHITE, true), 12);
        add(root, label("Основа интерфейса уже работает. Регистрация, переписка с шифрованием и синхронизация с сервером пока находятся в разработке.", 15, MUTED, false), 10);

        add(root, label("ТВОЁ ПРОСТРАНСТВО", 11, PURPLE, true), 38);
        root.addView(card("Избранное", "Личное пространство для заметок самому себе"));
        root.addView(card("Личные чаты", "Здесь будут отображаться диалоги один на один"));
        root.addView(card("Группы", "Здесь будут отображаться групповые беседы"));
        root.addView(card("Приватные каналы", "Каналы, доступные только по приглашению"));

        TextView footer = label("K.C.H.  •  FOUNDATION BUILD", 10, MUTED, false);
        footer.setGravity(Gravity.CENTER);
        add(root, footer, 34);

        TextView credits = label("kach0ta  ·  vo1dka  ·  r3z0n  ·  a1r1s", 8, Color.rgb(83, 78, 94), false);
        credits.setGravity(Gravity.CENTER);
        credits.setAlpha(0.55f);
        add(root, credits, 12);
        setContentView(scroll);
    }

    private View card(String title, String description) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(15), dp(16), dp(15));
        box.setBackgroundColor(PANEL);
        LinearLayout.LayoutParams p = params();
        p.topMargin = dp(10);
        box.setLayoutParams(p);
        box.addView(label(title, 17, Color.WHITE, true));
        add(box, label(description, 12, MUTED, false), 5);
        return box;
    }

    private TextView label(String value, int size, int color, boolean bold) {
        TextView v = new TextView(this);
        v.setText(value);
        v.setTextSize(size);
        v.setTextColor(color);
        if (bold) v.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return v;
    }

    private void add(LinearLayout parent, View child, int top) {
        LinearLayout.LayoutParams p = params();
        p.topMargin = dp(top);
        parent.addView(child, p);
    }

    private LinearLayout.LayoutParams params() {
        return new LinearLayout.LayoutParams(-1, -2);
    }

    private int dp(int n) {
        return (int)(n * getResources().getDisplayMetrics().density + 0.5f);
    }
}
