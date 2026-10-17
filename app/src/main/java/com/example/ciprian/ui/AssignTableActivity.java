package com.example.ciprian.ui;

import android.os.Bundle;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.example.ciprian.CiprianApp;
import com.example.ciprian.R;
import com.example.ciprian.data.ApiClient;
import com.example.ciprian.databinding.ActivityAssignTableBinding;

import java.util.ArrayList;
import java.util.List;

/**
 * Atribuie un cip (uid) unei mese: alegi restaurant -> masă -> Bind.
 * Consumă endpoint-urile /api/dinedroid/{restaurants,restaurants/:id/tables,tables/:id/bind}.
 * Cere un cont NFC legat de un user dinedroid (SUPER_ADMIN vede toate restaurantele).
 */
public class AssignTableActivity extends AppCompatActivity {

    private ActivityAssignTableBinding binding;
    private ApiClient api;

    private String tagUid;

    private ApiClient.DinedroidRestaurant[] restaurants = new ApiClient.DinedroidRestaurant[0];
    private ApiClient.DinedroidTable[] tables = new ApiClient.DinedroidTable[0];
    private int selectedRestaurantId = -1;
    private int selectedTableId = -1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);

        binding = ActivityAssignTableBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        ViewCompat.setOnApplyWindowInsetsListener(binding.getRoot(), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        api = CiprianApp.getInstance().getApiClient();

        tagUid = getIntent().getStringExtra("tag_uid");
        String tagName = getIntent().getStringExtra("tag_name");
        if (tagUid == null || tagUid.isEmpty()) {
            Toast.makeText(this, R.string.error, Toast.LENGTH_SHORT).show();
            finish();
            return;
        }
        binding.textTagInfo.setText(getString(R.string.assign_tag_info,
                tagName != null && !tagName.isEmpty() ? tagName : "-", tagUid));

        binding.toolbar.setNavigationOnClickListener(v -> finish());
        binding.dropdownRestaurant.setOnItemClickListener((p, v, pos, id) -> onRestaurantSelected(pos));
        binding.dropdownTable.setOnItemClickListener((p, v, pos, id) -> onTableSelected(pos));
        binding.btnBind.setOnClickListener(v -> bind());

        loadRestaurants();
    }

    private void loadRestaurants() {
        setLoading(true, getString(R.string.loading_restaurants));
        api.getDinedroidRestaurants(new ApiClient.ApiCallback<ApiClient.RestaurantListResponse>() {
            @Override public void onSuccess(ApiClient.RestaurantListResponse resp) {
                runOnUiThread(() -> {
                    setLoading(false, null);
                    restaurants = resp != null && resp.restaurants != null
                            ? resp.restaurants : new ApiClient.DinedroidRestaurant[0];
                    if (restaurants.length == 0) {
                        showStatus(getString(R.string.no_restaurants));
                        return;
                    }
                    List<String> names = new ArrayList<>();
                    for (ApiClient.DinedroidRestaurant r : restaurants) {
                        names.add(r.name != null ? r.name : ("#" + r.id));
                    }
                    binding.dropdownRestaurant.setAdapter(
                            new ArrayAdapter<>(AssignTableActivity.this,
                                    android.R.layout.simple_list_item_1, names));
                });
            }
            @Override public void onError(String error) {
                runOnUiThread(() -> { setLoading(false, null); showStatus(error); });
            }
        });
    }

    private void onRestaurantSelected(int pos) {
        if (pos < 0 || pos >= restaurants.length) return;
        selectedRestaurantId = restaurants[pos].id;

        // reset masă
        selectedTableId = -1;
        binding.dropdownTable.setText("", false);
        binding.dropdownTable.setAdapter(null);
        binding.inputTable.setEnabled(false);
        binding.btnBind.setEnabled(false);

        loadTables(selectedRestaurantId);
    }

    private void loadTables(int restaurantId) {
        setLoading(true, getString(R.string.loading_tables));
        api.getDinedroidTables(restaurantId, new ApiClient.ApiCallback<ApiClient.TableListResponse>() {
            @Override public void onSuccess(ApiClient.TableListResponse resp) {
                runOnUiThread(() -> {
                    setLoading(false, null);
                    tables = resp != null && resp.tables != null
                            ? resp.tables : new ApiClient.DinedroidTable[0];
                    if (tables.length == 0) {
                        showStatus(getString(R.string.no_tables));
                        return;
                    }
                    List<String> labels = new ArrayList<>();
                    for (ApiClient.DinedroidTable t : tables) labels.add(tableLabel(t));
                    binding.dropdownTable.setAdapter(
                            new ArrayAdapter<>(AssignTableActivity.this,
                                    android.R.layout.simple_list_item_1, labels));
                    binding.inputTable.setEnabled(true);
                });
            }
            @Override public void onError(String error) {
                runOnUiThread(() -> { setLoading(false, null); showStatus(error); });
            }
        });
    }

    private String tableLabel(ApiClient.DinedroidTable t) {
        String base = getString(R.string.table_label,
                t.number != null ? String.valueOf(t.number) : String.valueOf(t.id));
        if (t.programmed) base += " · " + getString(R.string.already_programmed);
        return base;
    }

    private void onTableSelected(int pos) {
        if (pos < 0 || pos >= tables.length) return;
        selectedTableId = tables[pos].id;
        binding.btnBind.setEnabled(true);
    }

    private void bind() {
        if (selectedTableId < 0) return;
        setLoading(true, getString(R.string.binding));
        binding.btnBind.setEnabled(false);
        api.bindTagToTable(selectedTableId, tagUid, new ApiClient.ApiCallback<ApiClient.BindTagResponse>() {
            @Override public void onSuccess(ApiClient.BindTagResponse resp) {
                runOnUiThread(() -> {
                    setLoading(false, null);
                    Toast.makeText(AssignTableActivity.this, R.string.bind_success, Toast.LENGTH_LONG).show();
                    setResult(RESULT_OK);
                    finish();
                });
            }
            @Override public void onError(String error) {
                runOnUiThread(() -> {
                    setLoading(false, null);
                    binding.btnBind.setEnabled(true);
                    showStatus(error);
                });
            }
        });
    }

    private void setLoading(boolean loading, String message) {
        binding.progress.setVisibility(loading ? View.VISIBLE : View.GONE);
        if (message != null) showStatus(message);
        else binding.textStatus.setVisibility(View.GONE);
    }

    private void showStatus(String message) {
        binding.textStatus.setText(message != null ? message : "");
        binding.textStatus.setVisibility(message != null ? View.VISIBLE : View.GONE);
    }
}
