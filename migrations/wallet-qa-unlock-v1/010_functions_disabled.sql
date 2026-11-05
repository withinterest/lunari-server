-- QA only: external metadata/TLS/SCRAM-PLUS verification is additionally mandatory.
-- Run within ONE separately approved installer transaction. Never an automatic migration.
DO $$ BEGIN
 IF current_database()<>'neondb' OR session_user<>'neondb_owner' OR current_user<>session_user
 OR current_setting('server_version_num')<>'180006'
 OR current_setting('lunari.wallet_v2_qa_target',true) IS DISTINCT FROM 'round-credit-14510227/br-restless-grass-b3odflam/ep-silent-leaf-b3xp84bu'
 OR current_setting('lunari.qa_unlock_install_approved',true) IS DISTINCT FROM '1'
 THEN RAISE EXCEPTION 'QA_UNLOCK_INSTALL_REFUSED'; END IF;
END $$;
CREATE SCHEMA wallet_v2_qa_test AUTHORIZATION neondb_owner;
REVOKE ALL ON SCHEMA wallet_v2_qa_test FROM PUBLIC;
GRANT USAGE ON SCHEMA wallet_v2_qa_test TO lunari_wallet_v2_fn_owner_qa,lunari_wallet_v2_issuer_sql_qa,lunari_wallet_v2_exec_sql_qa;
GRANT lunari_wallet_v2_fn_owner_qa TO neondb_owner WITH ADMIN FALSE,INHERIT FALSE,SET TRUE;
GRANT CREATE ON SCHEMA wallet_v2_qa_test TO lunari_wallet_v2_fn_owner_qa;
SET LOCAL ROLE lunari_wallet_v2_fn_owner_qa;
CREATE FUNCTION wallet_v2_qa_test.issue_unlock_context(u text,p jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE token text;
BEGIN
 IF current_database()<>'neondb' OR session_user<>'lunari_wallet_v2_issuer_sql_qa' OR current_user<>'lunari_wallet_v2_fn_owner_qa' THEN RAISE EXCEPTION 'QA_UNLOCK_ISSUER_REQUIRED';END IF;
 IF u IS NULL OR length(u) NOT BETWEEN 1 AND 128 OR u<>btrim(u) OR u~'[[:cntrl:]]' THEN RAISE EXCEPTION 'QA_UNLOCK_PRINCIPAL_REFUSED';END IF;
 IF p IS NULL OR jsonb_typeof(p)<>'object' OR octet_length(p::text)>512 THEN RAISE EXCEPTION 'QA_UNLOCK_PAYLOAD_REFUSED';END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(p))<>2 OR NOT(p ?& ARRAY['requestKey','contentId'])
 OR jsonb_typeof(p->'requestKey') IS DISTINCT FROM 'string' OR (p->>'requestKey')!~'^qa-unlock:[a-f0-9]{32}$'
 OR p->>'contentId' IS DISTINCT FROM 'qa_wallet_unlock_2stars_v1'
 THEN RAISE EXCEPTION 'QA_UNLOCK_PAYLOAD_REFUSED';END IF;
 token:=replace(gen_random_uuid()::text,'-','')||replace(gen_random_uuid()::text,'-','');
 INSERT INTO wallet_v2_secure.contexts(token_hash,user_uid,mode,operation,payload_hash,expires_at)
 VALUES(encode(sha256(convert_to(token,'UTF8')),'hex'),u,'google','qa_unlock_2stars_v1',encode(sha256(convert_to(p::text,'UTF8')),'hex'),clock_timestamp()+interval '2 minutes');
 RETURN token;
END $$;
CREATE FUNCTION wallet_v2_qa_test.unlock_content_2stars(token text,p jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE c record;u text;r jsonb;w record;prior uuid;tid uuid;
BEGIN
 IF current_database()<>'neondb' OR session_user<>'lunari_wallet_v2_exec_sql_qa' OR current_user<>'lunari_wallet_v2_fn_owner_qa' THEN RAISE EXCEPTION 'QA_UNLOCK_EXECUTOR_REQUIRED';END IF;
 IF p IS NULL OR jsonb_typeof(p)<>'object' OR octet_length(p::text)>512 THEN RAISE EXCEPTION 'QA_UNLOCK_PAYLOAD_REFUSED';END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(p))<>2 OR NOT(p ?& ARRAY['requestKey','contentId'])
 OR jsonb_typeof(p->'requestKey') IS DISTINCT FROM 'string' OR (p->>'requestKey')!~'^qa-unlock:[a-f0-9]{32}$'
 OR p->>'contentId' IS DISTINCT FROM 'qa_wallet_unlock_2stars_v1'
 THEN RAISE EXCEPTION 'QA_UNLOCK_PAYLOAD_REFUSED';END IF;
 IF token IS NULL OR token!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'QA_UNLOCK_CONTEXT_REFUSED';END IF;
 SELECT * INTO c FROM wallet_v2_secure.contexts WHERE token_hash=encode(sha256(convert_to(token,'UTF8')),'hex') FOR UPDATE;
 IF NOT FOUND OR c.used OR c.mode<>'google' OR c.operation<>'qa_unlock_2stars_v1'
 OR c.payload_hash<>encode(sha256(convert_to(p::text,'UTF8')),'hex') OR c.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'QA_UNLOCK_CONTEXT_REFUSED';END IF;
 UPDATE wallet_v2_secure.contexts SET used=true WHERE token_hash=c.token_hash;
 SET CONSTRAINTS public.wallet_v2_wallet_check,public.wallet_v2_ledger_check,public.wallet_v2_funding_check,public.wallet_v2_lot_check,public.wallet_v2_movement_check DEFERRED;
 u:=c.user_uid;r:=wallet_v2_secure.begin_request(u,'google','qa_unlock_2stars_v1',p);IF r IS NOT NULL THEN RETURN r;END IF;
 PERFORM wallet_v2_secure.assert_active(u);
 SELECT transaction_id INTO prior FROM public.star_wallet_unlocks WHERE user_uid=u AND content_id='qa_wallet_unlock_2stars_v1';
 IF FOUND THEN RETURN wallet_v2_secure.finish_request(u,'google','qa_unlock_2stars_v1',p,wallet_v2_secure.snapshot(u,'google')||jsonb_build_object('status','committed','alreadyApplied',true,'transactionId',prior));END IF;
 SELECT * INTO w FROM public.star_wallets WHERE user_uid=u FOR UPDATE;
 -- This QA experiment is free-only. Never fall back to paid stars, even if total >= 2.
 IF w.free_balance<2 THEN RAISE EXCEPTION 'QA_UNLOCK_INSUFFICIENT_FREE_STARS';END IF;
 r:=wallet_v2_secure.move(u,p->>'requestKey','unlock',-2,0,NULL,'qa_wallet_unlock_2stars_v1');tid:=(r->>'transactionId')::uuid;
 INSERT INTO public.star_wallet_unlocks(user_uid,content_id,transaction_id) VALUES(u,'qa_wallet_unlock_2stars_v1',tid);
 RETURN wallet_v2_secure.finish_request(u,'google','qa_unlock_2stars_v1',p,r||jsonb_build_object('contentId','qa_wallet_unlock_2stars_v1'));
END $$;
REVOKE ALL ON FUNCTION wallet_v2_qa_test.issue_unlock_context(text,jsonb) FROM PUBLIC,lunari_wallet_v2_issuer_sql_qa,lunari_wallet_v2_exec_sql_qa,lunari_wallet_v2_review_sql_qa,lunari_wallet_api_check;
REVOKE ALL ON FUNCTION wallet_v2_qa_test.unlock_content_2stars(text,jsonb) FROM PUBLIC,lunari_wallet_v2_issuer_sql_qa,lunari_wallet_v2_exec_sql_qa,lunari_wallet_v2_review_sql_qa,lunari_wallet_api_check;
RESET ROLE;
REVOKE CREATE ON SCHEMA wallet_v2_qa_test FROM lunari_wallet_v2_fn_owner_qa;
REVOKE lunari_wallet_v2_fn_owner_qa FROM neondb_owner GRANTED BY neondb_owner;
