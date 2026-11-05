-- QA only: external metadata/TLS/SCRAM-PLUS verification is additionally mandatory.
-- Run within ONE separately approved installer transaction. Never an automatic migration.
DO $$ BEGIN
 IF current_database()<>'neondb' OR session_user<>'neondb_owner' OR current_user<>session_user
 OR current_setting('server_version_num')<>'180006'
 OR current_setting('lunari.wallet_v2_qa_target',true) IS DISTINCT FROM 'round-credit-14510227/br-restless-grass-b3odflam/ep-silent-leaf-b3xp84bu'
 OR current_setting('lunari.qa_unlock_install_approved',true) IS DISTINCT FROM '1'
 THEN RAISE EXCEPTION 'QA_UNLOCK_INSTALL_REFUSED'; END IF;
END $$;
DO $$ BEGIN
 IF current_setting('lunari.qa_unlock_execute_approved',true) IS DISTINCT FROM '1' THEN RAISE EXCEPTION 'QA_UNLOCK_EXECUTE_NOT_APPROVED';END IF;
END $$;
GRANT lunari_wallet_v2_fn_owner_qa TO neondb_owner WITH ADMIN FALSE,INHERIT FALSE,SET TRUE;
SET LOCAL ROLE lunari_wallet_v2_fn_owner_qa;
GRANT EXECUTE ON FUNCTION wallet_v2_qa_test.issue_unlock_context(text,jsonb) TO lunari_wallet_v2_issuer_sql_qa;
GRANT EXECUTE ON FUNCTION wallet_v2_qa_test.unlock_content_2stars(text,jsonb) TO lunari_wallet_v2_exec_sql_qa;
RESET ROLE;
REVOKE lunari_wallet_v2_fn_owner_qa FROM neondb_owner GRANTED BY neondb_owner;
