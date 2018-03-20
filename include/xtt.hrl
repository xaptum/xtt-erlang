%%%-------------------------------------------------------------------
%%% @author iguberman
%%% @copyright (C) 2018, Xaptum, Inc.
%%% @doc
%%%
%%% @end
%%% Created : 19. Mar 2018 5:28 PM
%%%-------------------------------------------------------------------
-author("iguberman").

-define(XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512, 1).
-define(XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B, 2).
-define(XTT_X25519_LRSW_ED25519_AES256GCM_SHA512, 3).
-define(XTT_X25519_LRSW_ED25519_AES256GCM_BLAKE2B, 4).

-define(XTT_VERSION_ONE, 1).

-define(XTT_IDENTITY_SIZE, 16).

-define(XTT_GROUP_ID_SIZE, 32).
-define(XTT_DAA_CREDENTIAL_SIZE, 260).
-define(XTT_DAA_PRIV_KEY_SIZE, 32).
-define(XTT_DAA_GROUP_PUB_KEY_SIZE, 258).
-define(XTT_DAA_SIGNATURE_SIZE, 389).
-define(XTT_DAA_PSEUDONUM_SIZE, 65).

%%/* Diffie-Hellman */
%%typedef struct {unsigned char data[32];} xtt_x25519_pub_key;
%%typedef struct {unsigned char data[32];} xtt_x25519_priv_key;
%%typedef struct {unsigned char data[32];} xtt_x25519_shared_secret;

%%typedef struct {unsigned char data[16];} xtt_identity_type;

-define(DEFAULT_DATA_DIR, ".").

%% DEFAULT FILENAMES
-define(REQUESTED_CLIENT_ID_FILE, "requested_client_id.bin").
-define(SERVER_ID_FILE, "server_id.bin").
-define(DAA_GPK_FILE, "daa_gpk.bin").
-define(DAA_CRED_FILE, "daa_cred.bin").
-define(DAA_SECRETKEY_FILE, "daa_secretkey.bin").
-define(BASENAME_FILE, "basename.bin").
-define(ROOT_ID_FILE, "root_id.bin").
-define(ROOT_PUBKEY_FILE, "root_pub.bin").




