package com.example.ciprian.ui;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.example.ciprian.R;
import com.example.ciprian.data.ApiClient;
import com.example.ciprian.databinding.ItemTagBinding;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

public class TagsAdapter extends RecyclerView.Adapter<TagsAdapter.TagViewHolder> {

    private final List<ApiClient.TagItem> tags;
    private final OnTagClickListener listener;

    public interface OnTagClickListener {
        void onTagClick(ApiClient.TagItem tag);
    }

    public TagsAdapter(List<ApiClient.TagItem> tags, OnTagClickListener listener) {
        this.tags = tags;
        this.listener = listener;
    }

    @NonNull
    @Override
    public TagViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        ItemTagBinding binding = ItemTagBinding.inflate(
                LayoutInflater.from(parent.getContext()), parent, false);
        return new TagViewHolder(binding);
    }

    @Override
    public void onBindViewHolder(@NonNull TagViewHolder holder, int position) {
        holder.bind(tags.get(position));
    }

    @Override
    public int getItemCount() {
        return tags.size();
    }

    class TagViewHolder extends RecyclerView.ViewHolder {
        private final ItemTagBinding binding;

        TagViewHolder(ItemTagBinding binding) {
            super(binding.getRoot());
            this.binding = binding;
        }

        void bind(ApiClient.TagItem tag) {
            binding.textTagName.setText(tag.name != null ? tag.name : "Unnamed Tag");
            binding.textTagUid.setText(formatUid(tag.uid));
            binding.textScanCount.setText(String.valueOf(tag.scanCount));
            binding.textLastScan.setText(formatRelativeTime(tag.lastScan));

            binding.getRoot().setOnClickListener(v -> listener.onTagClick(tag));

            binding.buttonMore.setOnClickListener(v -> {
                // Show popup menu
                showPopupMenu(v, tag);
            });
        }

        private String formatUid(String uid) {
            if (uid == null || uid.length() < 2) return uid;
            StringBuilder formatted = new StringBuilder();
            for (int i = 0; i < uid.length(); i += 2) {
                if (i > 0) formatted.append(":");
                formatted.append(uid.substring(i, Math.min(i + 2, uid.length())));
            }
            return formatted.toString();
        }

        private String formatRelativeTime(String isoDate) {
            if (isoDate == null || isoDate.isEmpty()) {
                return itemView.getContext().getString(R.string.never);
            }

            try {
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
                Date date = sdf.parse(isoDate);
                if (date == null) return isoDate;

                long diffMs = System.currentTimeMillis() - date.getTime();
                long diffMins = TimeUnit.MILLISECONDS.toMinutes(diffMs);
                long diffHours = TimeUnit.MILLISECONDS.toHours(diffMs);
                long diffDays = TimeUnit.MILLISECONDS.toDays(diffMs);

                if (diffMins < 1) return "Just now";
                if (diffMins < 60) return diffMins + " min ago";
                if (diffHours < 24) return diffHours + "h ago";
                if (diffDays < 7) return diffDays + "d ago";

                SimpleDateFormat outFormat = new SimpleDateFormat("MMM d", Locale.US);
                return outFormat.format(date);
            } catch (ParseException e) {
                return isoDate;
            }
        }

        private void showPopupMenu(View anchor, ApiClient.TagItem tag) {
            android.widget.PopupMenu popup = new android.widget.PopupMenu(anchor.getContext(), anchor);
            popup.getMenuInflater().inflate(R.menu.tag_popup_menu, popup.getMenu());
            popup.setOnMenuItemClickListener(item -> {
                // Handle menu items
                return true;
            });
            popup.show();
        }
    }
}
