package com.example.ciprian.ui;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.ArrayAdapter;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.recyclerview.widget.LinearLayoutManager;

import com.example.ciprian.CiprianApp;
import com.example.ciprian.R;
import com.example.ciprian.data.ApiClient;
import com.example.ciprian.databinding.ActivityTablesBinding;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Alegi un restaurant -> vezi toate mesele lui -> apesi pe o masa ca sa scrii un
 * cip pentru ea. Cipul se leaga automat de masa dupa scriere (bind-ul e facut de
 * ProgramTagActivity, care primeste table_id prin intent).
 *
 * Restaurantul ales e retinut in prefs, ca sa nu-l reselectezi la fiecare cip.
 */
public class TablesActivity extends AppCompatActivity {

    private static final String PREFS = "ciprian_tables";
    private static final String KEY_LAST_RESTAURANT = "last_restaurant_id";

    private ActivityTablesBinding binding;
    private ApiClient api;
    private TablesAdapter adapter;

    private final List<ApiClient.DinedroidTable> tables = new ArrayList<>();
    private ApiClient.DinedroidRestaurant[] restaurants = new ApiClient.DinedroidRestaurant[0];
    private int selectedRestaurantId = -1;
    private String selectedRestaurantName;

    /** Eticheta unei mese: numarul daca exista, altfel id-ul. */
    static String tableName(Context ctx, ApiClient.DinedroidTable t) {
        return ctx.getString(R.string.table_label,
                t.number != null ? String.valueOf(t.number) : String.valueOf(t.id));
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);

        binding = ActivityTablesBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        ViewCompat.setOnApplyWindowInsetsListener(binding.getRoot(), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        api = CiprianApp.getInstance().getApiClient();

        binding.toolbar.setNavigationOnClickListener(v -> finish());
        binding.dropdownRestaurant.setOnItemClickListener((p, v, pos, id) -> onRestaurantSelected(pos, true));
        binding.swipeRefresh.setOnRefreshListener(() -> {
            if (selectedRestaurantId > 0) loadTables(selectedRestaurantId);
            else binding.swipeRefresh.setRefreshing(false);
        });

        adapter = new TablesAdapter(tables, this::onTableClick);
        binding.recyclerTables.setLayoutManager(new LinearLayoutManager(this));
        binding.recyclerTables.setAdapter(adapter);

        loadRestaurants();
    }

    @Override
    protected void onResume() {
        super.onResume();
        // Reintors din programare: reimprospatam ca masa sa apara ca avand cip.
        if (selectedRestaurantId > 0) loadTables(selectedRestaurantId);
    }

    private void loadRestaurants() {
        setLoading(true);
        showStatus(getString(R.string.loading_restaurants));
        api.getDinedroidRestaurants(new ApiClient.ApiCallback<ApiClient.RestaurantListResponse>() {
            @Override public void onSuccess(ApiClient.RestaurantListResponse resp) {
                runOnUiThread(() -> {
                    setLoading(false);
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
                    binding.dropdownRestaurant.setAdapter(new ArrayAdapter<>(
                            TablesActivity.this, android.R.layout.simple_list_item_1, names));

                    // Reselectam ultimul restaurant folosit, daca mai e disponibil.
                    int last = getSharedPreferences(PREFS, MODE_PRIVATE)
                            .getInt(KEY_LAST_RESTAURANT, -1);
                    int pos = indexOfRestaurant(last);
                    if (pos >= 0) {
                        binding.dropdownRestaurant.setText(names.get(pos), false);
                        onRestaurantSelected(pos, false);
                    } else {
                        showStatus(getString(R.string.pick_restaurant_hint));
                    }
                });
            }
            @Override public void onError(String error) {
                runOnUiThread(() -> { setLoading(false); showStatus(error); });
            }
        });
    }

    private int indexOfRestaurant(int id) {
        for (int i = 0; i < restaurants.length; i++) {
            if (restaurants[i].id == id) return i;
        }
        return -1;
    }

    private void onRestaurantSelected(int pos, boolean remember) {
        if (pos < 0 || pos >= restaurants.length) return;
        selectedRestaurantId = restaurants[pos].id;
        selectedRestaurantName = restaurants[pos].name;
        if (remember) {
            getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                    .putInt(KEY_LAST_RESTAURANT, selectedRestaurantId).apply();
        }
        loadTables(selectedRestaurantId);
    }

    private void loadTables(int restaurantId) {
        setLoading(true);
        api.getDinedroidTables(restaurantId, new ApiClient.ApiCallback<ApiClient.TableListResponse>() {
            @Override public void onSuccess(ApiClient.TableListResponse resp) {
                runOnUiThread(() -> {
                    setLoading(false);
                    tables.clear();
                    if (resp != null && resp.tables != null) tables.addAll(Arrays.asList(resp.tables));
                    adapter.notifyDataSetChanged();
                    showStatus(tables.isEmpty() ? getString(R.string.no_tables) : null);
                });
            }
            @Override public void onError(String error) {
                runOnUiThread(() -> {
                    setLoading(false);
                    tables.clear();
                    adapter.notifyDataSetChanged();
                    showStatus(error);
                });
            }
        });
    }

    /** Deschide programarea pentru masa aleasa; bind-ul se face automat dupa scriere. */
    private void onTableClick(ApiClient.DinedroidTable table) {
        Intent intent = new Intent(this, ProgramTagActivity.class);
        intent.putExtra("table_id", table.id);
        intent.putExtra("table_label", tableName(this, table));
        intent.putExtra("restaurant_name", selectedRestaurantName);
        startActivity(intent);
    }

    private void setLoading(boolean loading) {
        binding.progress.setVisibility(loading ? View.VISIBLE : View.GONE);
        if (!loading) binding.swipeRefresh.setRefreshing(false);
    }

    private void showStatus(String message) {
        binding.textStatus.setText(message != null ? message : "");
        binding.textStatus.setVisibility(message != null ? View.VISIBLE : View.GONE);
    }
}
