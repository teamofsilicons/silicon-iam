#!/usr/bin/env ruby
# frozen_string_literal: true

require "minitest/autorun"
require_relative "sql_comments"

class MigrationSecurityTest < Minitest::Test
  def bypass?(source)
    SqlComments.remove(source).match?(/\bBYPASSRLS\b/i)
  end

  def test_explanatory_comments_do_not_grant_privileges
    refute bypass?("-- A migrator is not a superuser or BYPASSRLS role.\nSELECT 1;")
    refute bypass?("/* no BYPASSRLS /* nested comment */ here */ SELECT 1;")
    refute bypass?("DO $$ BEGIN -- never grant BYPASSRLS\n RETURN; END $$;")
    refute bypass?("CREATE ROLE runtime NOBYPASSRLS;")
  end

  def test_direct_and_dynamic_privilege_sql_still_fails
    [
      "ALTER ROLE runtime BYPASSRLS;",
      "/* explanation */ CREATE ROLE runtime BYPASSRLS;",
      "DO $$ BEGIN EXECUTE 'ALTER ROLE runtime BYPASSRLS'; END $$;",
      "DO $body$ BEGIN EXECUTE $sql$ALTER ROLE runtime BYPASSRLS$sql$; END $body$;",
      "SELECT '--'; ALTER ROLE runtime BYPASSRLS;",
      "SELECT '/*'; ALTER ROLE runtime BYPASSRLS;",
      "SELECT $$--$$; ALTER ROLE runtime BYPASSRLS;",
      "SELECT $body$/*$body$; ALTER ROLE runtime BYPASSRLS;",
      "SELECT '-- it''s a value'; ALTER ROLE runtime BYPASSRLS;",
      'SELECT "--column"; ALTER ROLE runtime BYPASSRLS;'
    ].each { |sql| assert bypass?(sql), sql }
  end

  def test_public_execute_check_ignores_only_comments
    pattern = /\bGRANT\s+EXECUTE\b[^;]*\bTO\s+PUBLIC\b/im
    refute_match pattern, SqlComments.remove("-- GRANT EXECUTE ON FUNCTION f() TO PUBLIC;\nSELECT 1;")
    assert_match pattern, SqlComments.remove("GRANT /* split tokens */ EXECUTE ON FUNCTION f() TO PUBLIC;")
    assert_match pattern, SqlComments.remove("DO $$ BEGIN EXECUTE 'GRANT EXECUTE ON FUNCTION f() TO PUBLIC'; END $$;")
  end

  def test_comment_removal_preserves_line_numbers_and_unicode
    sql = "SELECT 'é'; /* one\n two */\n-- three\nSELECT 2;"
    cleaned = SqlComments.remove(sql)
    assert_equal sql.count("\n"), cleaned.count("\n")
    assert_includes cleaned, "'é'"
    assert_equal sql.encoding, cleaned.encoding
  end
end
