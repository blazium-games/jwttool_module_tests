extends AutoworkTest

var header_b64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
var payload_expired_b64 = "eyJzdWIiOiIxMjMiLCJleHAiOjE2MDAwMDAwMDB9"
var payload_valid_b64 = "eyJzdWIiOiIxMjMiLCJleHAiOjMzMjEzNDc1Mzh9"
var payload_no_exp_b64 = "eyJzdWIiOiIxMjMifQ"
var signature = "mock_signature_part"

var expired_jwt: String
var valid_jwt: String
var no_exp_jwt: String

func _before_all():
	expired_jwt = header_b64 + "." + payload_expired_b64 + "." + signature
	valid_jwt = header_b64 + "." + payload_valid_b64 + "." + signature
	no_exp_jwt = header_b64 + "." + payload_no_exp_b64 + "." + signature

func test_get_header():
	var header = JWT.get_header(valid_jwt)
	assert_true(header.has("alg"))
	assert_eq(String(header["alg"]), "HS256")
	assert_eq(String(header["typ"]), "JWT")

func test_get_payload():
	var payload = JWT.get_payload(valid_jwt)
	assert_true(payload.has("sub"))
	assert_eq(String(payload["sub"]), "123")

func test_get_signature():
	var sig = JWT.get_signature(valid_jwt)
	assert_eq(sig, signature)

func test_is_expired():
	assert_true(JWT.is_expired(expired_jwt))
	assert_false(JWT.is_expired(valid_jwt))
	assert_false(JWT.is_expired(no_exp_jwt))

func test_create_jwt_hs256():
	var header = {"alg": "HS256", "typ": "JWT"}
	var payload = {"sub": "123", "exp": 1600000000}
	var secret = "my_secret_key"
	
	var jwt_str = JWT.create_jwt_hs256(header, payload, secret)
	var get_sig = JWT.get_signature(jwt_str)
	var gen_header = JWT.get_header(jwt_str)
	var gen_payload = JWT.get_payload(jwt_str)
	
	assert_true(jwt_str.split(".").size() == 3)
	assert_eq(String(gen_header["alg"]), "HS256")
	assert_eq(String(gen_payload["sub"]), "123")
	assert_ne(get_sig, "")

func test_validate_signature_hs256():
	var header = {"alg": "HS256", "typ": "JWT"}
	var payload = {"sub": "123", "exp": 1600000000}
	var secret = "my_secret_key"
	
	var jwt_str = JWT.create_jwt_hs256(header, payload, secret)
	assert_true(JWT.validate_signature_hs256(jwt_str, secret))
	assert_false(JWT.validate_signature_hs256(jwt_str, "wrong_secret"))

func test_create_and_validate_jwt_rs256():
	var crypto = Crypto.new()
	var rsa_key = crypto.generate_rsa(2048)
	
	var header = {"alg": "RS256", "typ": "JWT"}
	var payload = {"sub": "rsa_user", "exp": 1600000000}
	
	var jwt_str = JWT.create_jwt_rs256(header, payload, rsa_key)
	
	assert_true(JWT.validate_signature_rs256(jwt_str, rsa_key))
	assert_eq(String(JWT.get_header(jwt_str)["alg"]), "RS256")
	assert_eq(String(JWT.get_payload(jwt_str)["sub"]), "rsa_user")
	
	var rsa_key_wrong = crypto.generate_rsa(2048)
	assert_false(JWT.validate_signature_rs256(jwt_str, rsa_key_wrong))

func test_claims_validation():
	var header = {"alg": "HS256", "typ": "JWT"}
	var payload = {"sub": "123", "aud": "blazium", "iss": "master", "exp": 1600000000}
	var secret = "secret_validation"
	var jwt_str = JWT.create_jwt_hs256(header, payload, secret)
	
	assert_true(JWT.has_claim(jwt_str, "sub"))
	assert_false(JWT.has_claim(jwt_str, "nonexistent"))
	
	assert_eq(String(JWT.get_claim(jwt_str, "aud")), "blazium")
	assert_eq(typeof(JWT.get_claim(jwt_str, "nonexistent")), TYPE_NIL)
	
	var expected_claims = {
		"sub": "123",
		"iss": "master"
	}
	assert_true(JWT.validate_claims(jwt_str, expected_claims))
	
	var bad_claims = {
		"sub": "123",
		"iss": "wrong_iss"
	}
	assert_false(JWT.validate_claims(jwt_str, bad_claims))

func test_validate_timing():
	var header = {"alg": "HS256", "typ": "JWT"}
	
	# Future exp -> valid
	var payload_good = {"exp": Time.get_unix_time_from_system() + 1000}
	var jwt_good = JWT.create_jwt_hs256(header, payload_good, "sec")
	assert_true(JWT.validate_timing(jwt_good))
	
	# Past exp -> invalid
	var payload_bad = {"exp": Time.get_unix_time_from_system() - 10}
	var jwt_bad = JWT.create_jwt_hs256(header, payload_bad, "sec")
	assert_false(JWT.validate_timing(jwt_bad))
	
	# Past exp but with leeway -> valid
	assert_true(JWT.validate_timing(jwt_bad, 15.0))
	
	# nbf in future -> invalid
	var payload_nbf = {"nbf": Time.get_unix_time_from_system() + 1000}
	var jwt_nbf = JWT.create_jwt_hs256(header, payload_nbf, "sec")
	assert_false(JWT.validate_timing(jwt_nbf))
	
	assert_eq(String(JWT.get_algorithm(jwt_good)), "HS256")

func test_universal_wrappers():
	var header_hs = {"alg": "HS256", "typ": "JWT"}
	var hs_secret = "universal_secret"
	var payload = {"sub": "wrap"}
	
	var hs_out = JWT.create_jwt(header_hs, payload, hs_secret)
	assert_true(JWT.validate(hs_out, hs_secret))
	assert_false(JWT.validate(hs_out, "bad"))
	
	var crypto = Crypto.new()
	var rs_key = crypto.generate_rsa(2048)
	var header_rs = {"alg": "RS256", "typ": "JWT"}
	
	var rs_out = JWT.create_jwt(header_rs, payload, rs_key)
	assert_true(JWT.validate(rs_out, rs_key))
	
	var wrong_rs_key = crypto.generate_rsa(2048)
	assert_false(JWT.validate(rs_out, wrong_rs_key))
	
	# Mismatched types return false gracefully
	assert_false(JWT.validate(rs_out, hs_secret))
	assert_false(JWT.validate(hs_out, rs_key))

func test_utilities():
	var header = {"alg": "HS256", "kid": "my_key"}
	var payload = {"sub": "tools"}
	var jwt_str = JWT.create_jwt(header, payload, "sec")
	
	# Test get_kid
	assert_eq(String(JWT.get_kid(jwt_str)), "my_key")
	
	# Test decode
	var decoded = JWT.decode(jwt_str)
	assert_true(decoded.has("header"))
	assert_true(decoded.has("payload"))
	assert_true(decoded.has("signature"))
	assert_eq(String(decoded["header"]["kid"]), "my_key")
	
	# Test base64url encode/decode
	var raw_str = "hello_base64!"
	var encoded = JWT.base64url_encode(raw_str)
	assert_ne(encoded, raw_str)
	assert_eq(encoded.find("="), -1) # base64url has no padding
	var decoded_str = JWT.base64url_decode(encoded)
	assert_eq(decoded_str, raw_str)

func test_rotations():
	# Test create_jwt_timed
	var header = {"alg": "HS256"}
	var payload = {"sub": "rotations"}
	var jwt_timed = JWT.create_jwt_timed(header, payload, "key_a", 3600)
	var decoded = JWT.decode(jwt_timed)
	assert_true(decoded["payload"].has("iat"))
	assert_true(decoded["payload"].has("exp"))
	assert_true(JWT.validate(jwt_timed, "key_a"))
	
	# Test validate_any
	var keys_array = ["bad_key", "another_bad_key", "key_a", "key_c"]
	assert_true(JWT.validate_any(jwt_timed, keys_array))
	var wrong_keys_array = ["bad_key", "another_bad_key"]
	assert_false(JWT.validate_any(jwt_timed, wrong_keys_array))
	
	# Test validate_with_map
	var header_with_kid = {"alg": "HS256", "kid": "key_b_id"}
	var jwt_kid = JWT.create_jwt(header_with_kid, payload, "key_b")
	
	var key_map = {
		"key_a_id": "key_a",
		"key_b_id": "key_b",
		"key_c_id": "key_c"
	}
	assert_true(JWT.validate_with_map(jwt_kid, key_map))
	
	var bad_map = {
		"key_a_id": "key_a"
	}
	assert_false(JWT.validate_with_map(jwt_kid, bad_map))

func test_diagnostics():
	var header = {"alg": "HS256"}
	var payload = {"sub": "diag", "aud": "admin"}
	var jwt_str = JWT.create_jwt(header, payload, "sec")
	
	# Test validate_diagnostic
	var d_valid = JWT.validate_diagnostic(jwt_str, "sec")
	assert_true(d_valid["valid"])
	assert_eq(String(d_valid["error"]), "")
	
	var d_bad_sig = JWT.validate_diagnostic(jwt_str, "wrong")
	assert_false(d_bad_sig["valid"])
	assert_eq(String(d_bad_sig["error"]), "Invalid HS256 signature.")
	
	var crypto = Crypto.new()
	var d_bad_type = JWT.validate_diagnostic(jwt_str, crypto.generate_rsa(2048))
	assert_false(d_bad_type["valid"])
	assert_eq(String(d_bad_type["error"]), "HS256 requires String secret.")
	
	# Test claims diagnostic
	var expected_claims = {"sub": "diag", "aud": "user", "role": "admin"}
	var claim_errs = JWT.validate_claims_diagnostic(jwt_str, expected_claims)
	assert_eq(claim_errs.size(), 2)
	assert_true("Mismatched claim: aud" in claim_errs)
	assert_true("Missing claim: role" in claim_errs)

func test_builders():
	var builder = JWTBuilder.new() \
		.set_algorithm("HS256") \
		.set_subject("user_build") \
		.set_issuer("engine") \
		.set_audience("clients") \
		.add_claim("role", "admin") \
		.set_expiration(3600)
	
	var jwt_str = builder.sign("build_secret")
	
	var decoded = JWT.decode(jwt_str)
	assert_eq(String(decoded["header"]["alg"]), "HS256")
	assert_eq(String(decoded["payload"]["sub"]), "user_build")
	assert_eq(String(decoded["payload"]["aud"]), "clients")
	assert_eq(String(decoded["payload"]["role"]), "admin")
	assert_true(decoded["payload"].has("exp"))
	assert_true(decoded["payload"].has("iat"))
	
	assert_true(JWT.validate(jwt_str, "build_secret"))

func test_parsed_objects():
	var builder = JWTBuilder.new() \
		.set_algorithm("HS256") \
		.set_subject("user_parsed") \
		.set_expiration(3600) \
		.add_claim("parsed_role", "admin")
	
	var jwt_str = builder.sign("sec")
	var token: DecodedJWT = JWT.parse(jwt_str)
	
	assert_eq(token.get_algorithm(), "HS256")
	assert_eq(String(token.get_claim("sub")), "user_parsed")
	assert_true(token.has_claim("parsed_role"))
	assert_eq(String(token.get_claim("parsed_role")), "admin")
	assert_false(token.has_claim("missing_role"))
	assert_false(token.is_expired())

func test_revocation():
	var builder = JWTBuilder.new() \
		.set_algorithm("HS256") \
		.set_jwt_id("session_982") \
		.set_expiration(3600)
	var jwt_str = builder.sign("sec")
	
	# Should be valid initially
	assert_true(JWT.validate(jwt_str, "sec"))
	
	# Revoke it
	JWT.revoke_jti("session_982")
	
	assert_true(JWT.is_revoked("session_982"))
	assert_false(JWT.validate(jwt_str, "sec"))
	
	var d_valid = JWT.validate_diagnostic(jwt_str, "sec")
	assert_false(d_valid["valid"])
	assert_eq(String(d_valid["error"]), "Token has been revoked (JTI match).")
	
	JWT.clear_revoked()
	assert_false(JWT.is_revoked("session_982"))
	assert_true(JWT.validate(jwt_str, "sec"))

func test_registered_claims():
	var builder = JWTBuilder.new() \
		.set_algorithm("HS256") \
		.set_issuer("auth.mygame.com") \
		.set_subject("user_404") \
		.set_audience("client_game") \
		.set_jwt_id("token_abc_123") \
		.set_expiration(3600)
		
	var jwt_str = builder.sign("sec")
	var token: DecodedJWT = JWT.parse(jwt_str)
	
	assert_eq(token.get_issuer(), "auth.mygame.com")
	assert_eq(token.get_subject(), "user_404")
	assert_eq(String(token.get_audience()), "client_game")
	assert_eq(token.get_jwt_id(), "token_abc_123")
	
	# Verify doubles logic constraints cleanly mapped natively
	assert_true(token.get_expiration_time() > 1000000.0)
	assert_true(token.get_issued_at() > 1000000.0)
	assert_eq(token.get_not_before(), 0.0)
	
func test_typed_claims():
	var builder = JWTBuilder.new() \
		.set_algorithm("HS256") \
		.add_claim("str_claim", "hello") \
		.add_claim("int_claim", 42) \
		.add_claim("bool_claim", true) \
		.add_claim("arr_claim", ["admin", "user"]) \
		.add_claim("dict_claim", {"key": "val"})
	
	var jwt_str = builder.sign("sec")
	var token: DecodedJWT = JWT.parse(jwt_str)
	
	assert_eq(token.get_claim_as_string("str_claim"), "hello")
	assert_eq(token.get_claim_as_string("int_claim"), "") 
	
	assert_eq(token.get_claim_as_int("int_claim"), 42)
	assert_eq(token.get_claim_as_int("str_claim"), 0) 
	
	assert_true(token.get_claim_as_bool("bool_claim"))
	assert_false(token.get_claim_as_bool("str_claim"))
	
	var arr = token.get_claim_as_array("arr_claim")
	assert_eq(arr.size(), 2)
	assert_eq(String(arr[0]), "admin")
	var empty_arr = token.get_claim_as_array("str_claim")
	assert_eq(empty_arr.size(), 0)
	
	var dict = token.get_claim_as_dictionary("dict_claim")
	assert_eq(String(dict["key"]), "val")
	var empty_dict = token.get_claim_as_dictionary("str_claim")
	assert_eq(empty_dict.size(), 0)

func test_audience_arrays():
	var builder = JWTBuilder.new() \
		.set_algorithm("HS256") \
		.add_claim("aud", ["game_client_1", "game_client_2"])
	var jwt_str = builder.sign("sec")
	
	# Audience string evaluating expected claim dynamically resolves internally
	var constraint = {"aud": "game_client_2"}
	assert_true(JWT.validate_claims(jwt_str, constraint))
	
	var constraint_fail = {"aud": "game_client_3"}
	assert_false(JWT.validate_claims(jwt_str, constraint_fail))
	
	# Header checking tests explicitly checking native headers
	var header_constraint = {"alg": "HS256", "typ": "JWT"}
	assert_true(JWT.validate_header_claims(jwt_str, header_constraint))
	
	var token: DecodedJWT = JWT.parse(jwt_str)
	assert_true(token.has_header_claim("alg"))
	assert_eq(token.get_header_claim_as_string("typ"), "JWT")
	assert_false(token.has_header_claim("missing_val"))
