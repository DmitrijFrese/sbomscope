package dev.sbomscope.scanner;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Storage for the parsed advisory index. Derived data: rebuildable from the archive. */
@Repository
public class OsvIndexRepository {

    private final JdbcClient jdbc;
    private final JdbcTemplate jdbcTemplate;

    OsvIndexRepository(JdbcClient jdbc, JdbcTemplate jdbcTemplate) {
        this.jdbc = jdbc;
        this.jdbcTemplate = jdbcTemplate;
    }

    /** One advisory against one package, with the affected entries as OSV wrote them. */
    public record IndexRow(String packageName, String osvId, String cveId, String rating, String affected) {}

    public record IndexSource(String ecosystem, String identity, int advisories, int packages, Instant builtAt) {}

    /**
     * Written in chunks as the archive streams, rather than accumulated and inserted once.
     *
     * <p>The whole point of persisting the index is not to hold 220,000 packages in memory;
     * building the row list first would hold them anyway, just in a different shape.
     */
    public void insertChunk(String ecosystem, List<IndexRow> rows) {
        if (rows.isEmpty()) {
            return;
        }
        jdbcTemplate.batchUpdate("""
                INSERT INTO osv_index (ecosystem, package_name, osv_id, cve_id, rating, affected)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                rows, rows.size(),
                (ps, row) -> {
                    ps.setString(1, ecosystem);
                    ps.setString(2, row.packageName());
                    ps.setString(3, row.osvId());
                    ps.setString(4, row.cveId());
                    ps.setString(5, row.rating());
                    ps.setString(6, row.affected());
                });
    }

    /** The selective read the whole design is for: one package, not one ecosystem. */
    public List<IndexRow> advisoriesFor(String ecosystem, String packageName) {
        return jdbc.sql("""
                SELECT package_name, osv_id, cve_id, rating, affected FROM osv_index
                WHERE ecosystem = ? AND package_name = ?
                """)
                .params(ecosystem, packageName)
                .query((rs, row) -> new IndexRow(
                        rs.getString("package_name"),
                        rs.getString("osv_id"),
                        rs.getString("cve_id"),
                        rs.getString("rating"),
                        rs.getString("affected")))
                .list();
    }

    public Optional<IndexSource> sourceFor(String ecosystem) {
        return jdbc.sql("SELECT * FROM osv_index_source WHERE ecosystem = ?")
                .param(ecosystem)
                .query((rs, row) -> new IndexSource(
                        rs.getString("ecosystem"),
                        rs.getString("identity"),
                        rs.getInt("advisories"),
                        rs.getInt("packages"),
                        rs.getObject("built_at", OffsetDateTime.class).toInstant()))
                .optional();
    }

    /** Clears one ecosystem before a rebuild, and when its archive is erased. */
    public void clear(String ecosystem) {
        jdbc.sql("DELETE FROM osv_index WHERE ecosystem = ?").param(ecosystem).update();
        jdbc.sql("DELETE FROM osv_index_source WHERE ecosystem = ?").param(ecosystem).update();
    }

    /**
     * Written last, deliberately.
     *
     * <p>It is what marks the index usable, so a build interrupted halfway leaves rows with
     * no source row — and the next start treats that as "not indexed" and rebuilds, rather
     * than answering questions from half an archive. The same reasoning as writing the
     * download to {@code all.zip.partial} before moving it into place.
     */
    public void recordSource(IndexSource source) {
        jdbc.sql("""
                INSERT INTO osv_index_source (ecosystem, identity, advisories, packages, built_at)
                VALUES (?, ?, ?, ?, ?)
                """)
                .params(source.ecosystem(), source.identity(), source.advisories(),
                        source.packages(), source.builtAt().atOffset(ZoneOffset.UTC))
                .update();
    }

    /** For the purge panel: how much derived data is sitting there. */
    public int countRows() {
        return jdbc.sql("SELECT COUNT(*) FROM osv_index").query(Integer.class).single();
    }
}
