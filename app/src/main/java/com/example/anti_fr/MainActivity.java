package com.example.anti_fr;

import android.graphics.Color;
import android.os.AsyncTask;
import android.os.Bundle;
import android.widget.Button;
import android.view.LayoutInflater;
import android.view.ViewGroup;
import android.view.View;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.LinearLayoutManager;

import com.kanxue.anti_fr.R;

import org.json.JSONObject;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private static boolean libLoaded = false;

    // JNI
    public static native void initHardening();
    public static native String runDetections();

    private final List<CheckItem> items = new ArrayList<>();
    private CheckAdapter adapter;
    private Button btnRun;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // ✅ 先加载UI
        setContentView(R.layout.activity_main);

        RecyclerView rv = findViewById(R.id.rv);
        rv.setLayoutManager(new LinearLayoutManager(this));
        adapter = new CheckAdapter(items);
        rv.setAdapter(adapter);

        // 初始化检测项目列表（立即显示 UI）
        items.add(new CheckItem("traced",            "TracerPid 调试",          "/proc/self/status TracerPid != 0"));
        items.add(new CheckItem("badMaps",           "maps 关键词",             "/proc/self/maps 出现 frida/xposed/zygisk/magisk 等"));
        items.add(new CheckItem("fridaPort",         "Frida 端口",              "/proc/net/tcp(tcp6) 27042/27043"));
        items.add(new CheckItem("badThreads",        "可疑线程名",              "/proc/self/task/*/comm 含 frida/xposed/zygisk"));
        //items.add(new CheckItem("suspiciousBranch",  "首指令可疑(arm64)",       "函数开头为 B/BR/BLR 跳转（启发式）"));
        adapter.notifyDataSetChanged();

        btnRun = findViewById(R.id.btnRun);
        // ✅ 按钮点击后再执行JNI检测逻辑
        btnRun.setOnClickListener(v -> runAll());
    }

    private void runAll() {
        btnRun.setEnabled(false);
        btnRun.setText("正在检测...");

        AsyncTask.THREAD_POOL_EXECUTOR.execute(() -> {
            try {
                // 延迟加载 so，避免启动卡顿
                if (!libLoaded) {
                    System.loadLibrary("antihook");
                    libLoaded = true;
                    initHardening();
                }

                String json = runDetections();
                JSONObject o = new JSONObject(json);
                for (CheckItem it : items) {
                    if (o.has(it.key)) it.bad = o.getBoolean(it.key);
                }
            } catch (Throwable t) {
                for (CheckItem it : items) it.bad = null;
            }

            runOnUiThread(() -> {
                adapter.notifyDataSetChanged();
                btnRun.setEnabled(true);
                btnRun.setText("开始检测");
            });
        });
    }

    // RecyclerView Adapter
    private static class CheckAdapter extends RecyclerView.Adapter<VH> {
        private final List<CheckItem> data;
        CheckAdapter(List<CheckItem> data) { this.data = data; }

        @NonNull @Override public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_check, parent, false);
            return new VH(v);
        }

        @Override public void onBindViewHolder(@NonNull VH h, int p) {
            CheckItem it = data.get(p);
            h.tvTitle.setText(it.title);
            h.tvDesc.setText(it.desc);
            if (it.bad == null) {
                h.tvResult.setText("未检测");
                h.tvResult.setTextColor(Color.GRAY);
            } else if (it.bad) {
                h.tvResult.setText("发现风险");
                h.tvResult.setTextColor(Color.parseColor("#D32F2F"));
            } else {
                h.tvResult.setText("未发现");
                h.tvResult.setTextColor(Color.parseColor("#2E7D32"));
            }
        }

        @Override public int getItemCount() { return data.size(); }
    }

    private static class VH extends RecyclerView.ViewHolder {
        TextView tvTitle, tvDesc, tvResult;
        VH(@NonNull View itemView) {
            super(itemView);
            tvTitle = itemView.findViewById(R.id.tvTitle);
            tvDesc  = itemView.findViewById(R.id.tvDesc);
            tvResult= itemView.findViewById(R.id.tvResult);
        }
    }
}
