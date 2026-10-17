package com.example.ciprian.ui;

import android.view.LayoutInflater;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.example.ciprian.R;
import com.example.ciprian.data.ApiClient;
import com.example.ciprian.databinding.ItemTableBinding;

import java.util.List;

/** Lista meselor unui restaurant; fiecare rând duce direct la scrierea unui cip. */
public class TablesAdapter extends RecyclerView.Adapter<TablesAdapter.TableViewHolder> {

    private final List<ApiClient.DinedroidTable> tables;
    private final OnTableClickListener listener;

    public interface OnTableClickListener {
        void onTableClick(ApiClient.DinedroidTable table);
    }

    public TablesAdapter(List<ApiClient.DinedroidTable> tables, OnTableClickListener listener) {
        this.tables = tables;
        this.listener = listener;
    }

    @NonNull
    @Override
    public TableViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        ItemTableBinding binding = ItemTableBinding.inflate(
                LayoutInflater.from(parent.getContext()), parent, false);
        return new TableViewHolder(binding);
    }

    @Override
    public void onBindViewHolder(@NonNull TableViewHolder holder, int position) {
        holder.bind(tables.get(position));
    }

    @Override
    public int getItemCount() {
        return tables.size();
    }

    class TableViewHolder extends RecyclerView.ViewHolder {
        private final ItemTableBinding binding;

        TableViewHolder(ItemTableBinding binding) {
            super(binding.getRoot());
            this.binding = binding;
        }

        void bind(ApiClient.DinedroidTable table) {
            binding.textTableName.setText(TablesActivity.tableName(itemView.getContext(), table));

            if (table.tagCount > 0) {
                binding.textTableStatus.setText(itemView.getResources().getQuantityString(
                        R.plurals.tags_on_table, table.tagCount, table.tagCount));
                binding.buttonProgramTable.setText(R.string.add_chip);
            } else {
                binding.textTableStatus.setText(R.string.no_tag_yet);
                binding.buttonProgramTable.setText(R.string.write_chip);
            }

            binding.getRoot().setOnClickListener(v -> listener.onTableClick(table));
            binding.buttonProgramTable.setOnClickListener(v -> listener.onTableClick(table));
        }
    }
}
