/*
 * Copyright (c) 2004 - 2008 Kungliga Tekniska H�gskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

/* $Id: mod_spnego.c 8454 2006-04-28 06:54:30Z lha $ */

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <mod_auth.h>
#include <apr_strings.h>
#include <apr_tables.h>

#ifdef HEIMDAL_FRAMEWORK
#include <Heimdal/gssapi.h>
#include <Heimdal/krb5.h>
#else
#include <gssapi.h>
#include <krb5.h>
#endif

extern module AP_MODULE_DECLARE_DATA spnego_module;

static const char *NEGOTIATE_NAME = "Negotiate";
static const char *NTLM_NAME = "NTLM";
static const char *WWW_AUTHENTICATE = "WWW-Authenticate";

#define SPNEGO_DEBUG(c, r, ...)						\
	do { if (c->spnego_debug) {					\
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,	\
			      0, r, __VA_ARGS__); }			\
	} while (0)

typedef struct {
    unsigned int spnego_on;
    unsigned int spnego_debug;
    char *spnego_name;
    unsigned int spnego_save_cred;
    char *spnego_krb5_acceptor_identity;
    unsigned int spnego_use_display_name;
    /* allowed mechs .... */
} spnego_config;

static const command_rec spnego_cmds[] = {
    AP_INIT_FLAG("SPNEGOAuth",
		 ap_set_flag_slot,
		 (void *)APR_OFFSETOF(spnego_config, spnego_on),
		 OR_AUTHCFG,
		 "set to 'on' to activate SPNEGO authentication"),
    AP_INIT_FLAG("SPNEGODebug",
		 ap_set_flag_slot,
		 (void *)APR_OFFSETOF(spnego_config, spnego_debug),
		 OR_AUTHCFG,
		 "set to 'on' to activate SPNEGO debuging"),
    AP_INIT_TAKE1("SPNEGOAuthAcceptorName",
		  ap_set_string_slot,
		  (void *)APR_OFFSETOF(spnego_config, spnego_name),
		  OR_AUTHCFG,
		  "The acceptor name imported into the GSS-API library"),
    AP_INIT_FLAG("SPNEGOAuthSaveDelegatedCred",
		 ap_set_flag_slot,
		 (void *)APR_OFFSETOF(spnego_config, spnego_save_cred),
		 OR_AUTHCFG,
		 "set to 'on' to save delegated gss-api authentication "
		 "(requires non standard API support from gssapi)"),

    AP_INIT_TAKE1("SPNEGOAuthKrb5AcceptorIdentity",
		  ap_set_string_slot,
		  (void *)APR_OFFSETOF(spnego_config, 
				       spnego_krb5_acceptor_identity),
		  OR_AUTHCFG,
		  "set to Kerberos 5 keytab filename "
		  "(valid iff compiled with krb5 support)"),
    AP_INIT_FLAG("SPNEGOUseDisplayName",
		 ap_set_flag_slot,
		 (void *)APR_OFFSETOF(spnego_config, spnego_use_display_name),
		 OR_AUTHCFG,
		 "set to 'on' to make SPNEGO use display name instead of "
		 "export name in REMOTE_USER"),
    { NULL }
};

static void *
spnego_dir_config(apr_pool_t * p, char *d)
{
    spnego_config *conf = (spnego_config *) apr_pcalloc(p, sizeof(spnego_config));

    /* Set the defaults. */

    conf->spnego_on = 0;
    conf->spnego_name = NULL;
    conf->spnego_save_cred = 0;
    conf->spnego_krb5_acceptor_identity = NULL;
    conf->spnego_use_display_name = 1;

    return conf;
}


static void
k5_save(request_rec * r, gss_cred_id_t cred)
{
#ifdef HAVE_KRB5
    krb5_context kcontext;
    krb5_error_code kret;
    OM_uint32 maj_stat, min_stat;
    krb5_ccache id;

    kret = krb5_init_context(&kcontext);
    if (kret)
	return;

    kret = krb5_cc_new_unique(kcontext, "FILE", NULL, &id);
    if (kret) {
	krb5_free_context(kcontext);
	return;
    }

    maj_stat = gss_krb5_copy_ccache(&min_stat, cred, id);
    if (maj_stat)
	krb5_cc_destroy(kcontext, id);
    else {
	const char *fn;

	fn = apr_psprintf(r->pool, "FILE:%s", krb5_cc_get_name(kcontext, id));

	krb5_cc_close(kcontext, id);
	apr_table_set(r->subprocess_env, "KRB5CCNAME", fn);
    }

    krb5_free_context(kcontext);
#endif
}

struct mech_specific {
    char *oid;
    size_t oid_len;
    void (*save_cred)(request_rec *, gss_cred_id_t);
} mechs[] = {
    { "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02", 9, k5_save },
    { NULL }
};

static const struct mech_specific *
find_mech(gss_OID oid)
{
    int i;

    for (i = 0; mechs[i].oid != NULL; i++) {
	if (oid->length != mechs[i].oid_len)
	    continue;
	if (memcmp(oid->elements, mechs[i].oid, mechs[i].oid_len) != 0)
	    continue;
	return &mechs[i];
    }
    return NULL;
}

static int 
check_user_id(request_rec *r)
{
    const struct mech_specific *m;
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc in, out;
    gss_cred_id_t delegated_cred_handle = NULL;
    gss_name_t src_name = GSS_C_NO_NAME;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    spnego_config *c;
    const char *p, *q;
    char *user, *reply;
    gss_OID oid;
    int ret;
    const char *mech = "unknown";

    c = ap_get_module_config(r->per_dir_config, &spnego_module);
    if (c == NULL || !c->spnego_on)
	return DECLINED;

    p = apr_table_get(r->headers_in, "Authorization");
    if (p == NULL) {
	SPNEGO_DEBUG(c, r, "mod_spnego: no Authorization header");
	apr_table_addn(r->err_headers_out, WWW_AUTHENTICATE, NEGOTIATE_NAME);
	apr_table_addn(r->err_headers_out, WWW_AUTHENTICATE, NTLM_NAME);
	return HTTP_UNAUTHORIZED;
    }

    mech = ap_getword_white(r->pool, &p);
    if (mech == NULL) {
	SPNEGO_DEBUG(c, r, "mod_spnego: Authorization header malformated");
	apr_table_addn(r->err_headers_out, WWW_AUTHENTICATE, NEGOTIATE_NAME);
	apr_table_addn(r->err_headers_out, WWW_AUTHENTICATE, NTLM_NAME);
	return HTTP_UNAUTHORIZED;
    }

    if (strcmp(mech, NEGOTIATE_NAME) != 0 && strcmp(mech, NTLM_NAME) != 0) {
	SPNEGO_DEBUG(c, r, "mod_spnego: auth not support: %s", mech);
	apr_table_addn(r->err_headers_out, WWW_AUTHENTICATE, NEGOTIATE_NAME);
	apr_table_addn(r->err_headers_out, WWW_AUTHENTICATE, NTLM_NAME);
	return HTTP_UNAUTHORIZED;
    }

    in.value = apr_palloc(r->pool, apr_base64_decode_len(p));
    in.length = apr_base64_decode_binary(in.value, p);

    out.length = 0;
    out.value = NULL;

#ifdef HAVE_KRB5
    if (c->spnego_krb5_acceptor_identity)
	krb5_gss_register_acceptor_identity(c->spnego_krb5_acceptor_identity);
#endif

    SPNEGO_DEBUG(c, r, "mod_spnego: calling ASC");

    maj_stat = gss_accept_sec_context(&min_stat,
				      &ctx,
				      GSS_C_NO_CREDENTIAL,
				      &in,
				      GSS_C_NO_CHANNEL_BINDINGS,
				      &src_name,
				      &oid,
				      &out,
				      NULL,
				      NULL,
				      &delegated_cred_handle);

    if ((maj_stat & GSS_S_CONTINUE_NEEDED)) {
	SPNEGO_DEBUG(c, r, "mod_spnego: continue needed, bad mech selected: %d", (int)out.length);
	ret = HTTP_UNAUTHORIZED;
	goto reply;
    } else if (maj_stat != GSS_S_COMPLETE) {
	OM_uint32 message_context = 0, min_stat2, ret;
	gss_buffer_desc error;

	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
		      "mod_spnego: accept_sec_context %d/%d",
		      maj_stat, min_stat);
	
	ret = gss_display_status(&min_stat2,
				 maj_stat, 
				 GSS_C_GSS_CODE,
				 GSS_C_NO_OID,
				 &message_context,
				 &error);
	if (ret == GSS_S_COMPLETE) {
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
			  "mod_spnego: major: %.*s", 
			  (int)error.length, (char *)error.value);
	    gss_release_buffer(&min_stat2, &error);
	}
	
	ret = gss_display_status(&min_stat2,
				 min_stat, 
				 GSS_C_MECH_CODE, 
				 GSS_C_NO_OID,
				 &message_context,
				 &error);
	if (ret == GSS_S_COMPLETE) {
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
			  "mod_spnego: minor: %.*s", 
			  (int)error.length, (char *)error.value);
	    gss_release_buffer(&min_stat2, &error);
	}

	ret = HTTP_UNAUTHORIZED;
	goto out;
    }
				      
    if (src_name == NULL) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
		      "mod_spnego: mech exported no src_name, failing",
		      maj_stat, min_stat);
	ret = HTTP_UNAUTHORIZED;
	goto out;
    }

    if (c->spnego_use_display_name) {
	gss_buffer_desc name;

	maj_stat = gss_display_name(&min_stat, src_name, &name, NULL);
	if (maj_stat != GSS_S_COMPLETE) {
	    SPNEGO_DEBUG(c, r, "mod_spnego: failed to display name");
	    ret = HTTP_UNAUTHORIZED;
	    goto out;
	}
    
	user = apr_palloc(r->connection->pool, name.length + 1);
	memcpy(user, name.value, name.length);
	user[name.length] = '\0';

	gss_release_buffer(&min_stat, &name);
    } else {
	gss_buffer_desc name;

	maj_stat = gss_export_name(&min_stat, src_name, &name);
	if (maj_stat != GSS_S_COMPLETE) {
	    SPNEGO_DEBUG(c, r, "mod_spnego: failed to export name");
	    ret = HTTP_UNAUTHORIZED;
	    goto out;
	}
    
	user = apr_palloc(r->connection->pool, 
			  apr_base64_encode_len(name.length));
	apr_base64_encode(user, name.value, name.length);

	gss_release_buffer(&min_stat, &name);
    }
    r->user = user;
    r->ap_auth_type = apr_pstrdup(r->connection->pool, NEGOTIATE_NAME);

    apr_table_set(r->subprocess_env, "NEGOTIATE_MECH", mech);
    apr_table_set(r->subprocess_env, "NEGOTIATE_INITIATOR_NAME", user);

    if (delegated_cred_handle && c->spnego_save_cred) {
	m = find_mech(oid);
	if (m && m->save_cred)
	    (*m->save_cred)(r, delegated_cred_handle);
    }

    ret = OK;

 reply:
    if (out.length) {
	size_t len;
	reply = apr_palloc(r->pool, apr_base64_encode_len(out.length) + 2);
	reply[0] = ' ';
	len = apr_base64_encode(reply + 1, out.value, out.length);
	reply[len + 1] = '\0';
    } else
	reply = NULL;
    
    apr_table_setn(r->headers_out, WWW_AUTHENTICATE,
		   apr_pstrcat(r->pool, mech, reply, NULL));

 out:
    SPNEGO_DEBUG(c, r, "mod_spnego: %s: done: %x/%x", mech, maj_stat, min_stat);
    if (src_name != GSS_C_NO_NAME)
	gss_release_name(&min_stat, &src_name);
    if (ctx != GSS_C_NO_CONTEXT)
	gss_delete_sec_context(&min_stat, &ctx, GSS_C_NO_BUFFER);
    if (out.value)
	gss_release_buffer(&min_stat, &out);
    if (delegated_cred_handle)
	gss_release_cred(&min_stat, &delegated_cred_handle);

    return ret;
}

static int
post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    /* 
     * turn off the reply cache, it just hurts us since browsers are
     * too fast and does the wrong thing.
     *
     * XXX should force running over https.
     */
    putenv(strdup("KRB5RCACHETYPE=none"));
    return OK;
}

static void
mod_spnego_register_hooks (apr_pool_t *p)
{
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id(check_user_id, NULL, NULL, APR_HOOK_MIDDLE);
}


module AP_MODULE_DECLARE_DATA spnego_module =
{
  STANDARD20_MODULE_STUFF,
  spnego_dir_config,
  NULL,
  NULL,
  NULL,
  spnego_cmds,
  mod_spnego_register_hooks
};
