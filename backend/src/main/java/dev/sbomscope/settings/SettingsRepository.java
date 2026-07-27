package dev.sbomscope.settings;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Key/value storage for user-editable application settings. */
@Repository
public class SettingsRepository {

    private final JdbcClient jdbc;

    SettingsRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<String> find(String key) {
        return jdbc.sql("SELECT setting_value FROM app_setting WHERE setting_key = ?")
                .param(key)
                .query(String.class)
                .optional();
    }

    public Map<String, String> findAll() {
        Map<String, String> values = new LinkedHashMap<>();
        jdbc.sql("SELECT setting_key, setting_value FROM app_setting")
                .query((rs, row) -> Map.entry(rs.getString("setting_key"),
                        Optional.ofNullable(rs.getString("setting_value")).orElse("")))
                .list()
                .forEach(entry -> values.put(entry.getKey(), entry.getValue()));
        return values;
    }

    /** Upsert, so callers never have to know whether the key already existed. */
    public void put(String key, String value) {
        OffsetDateTime now = Instant.now().atOffset(ZoneOffset.UTC);
        int updated = jdbc.sql("UPDATE app_setting SET setting_value = ?, updated_at = ? WHERE setting_key = ?")
                .params(value, now, key)
                .update();

        if (updated == 0) {
            jdbc.sql("INSERT INTO app_setting (setting_key, setting_value, updated_at) VALUES (?, ?, ?)")
                    .params(key, value, now)
                    .update();
        }
    }
}
