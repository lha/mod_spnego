/*
 * Copyright (c) 2004 - 2008 Kungliga Tekniska Högskolan
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

#include <gssapi.h>

#ifdef HAVE_KRB5
#include <krb5.h>
#endif

extern module AP_MODULE_DECLARE_DATA spnego_module;

#define NEGOTIATE_NAME "Negotiate"
#define WWW_AUTHENTICATE "WWW-Authenticate"

typedef struct {
    unsigned int spnego_on;
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
		 OR_AUTHCFG | RSRC_CONF,
		 "set to 'on' to activate SPNEGO authentication here"),
    AP_INIT_TAKE1("SPNEGOAuthAcceptorName",
		  ap_set_string_slot,
		  (void *)APR_OFFSETOF(spnego_config, spnego_name),
		  OR_AUTHCFG | RSRC_CONF,
		  "The acceptor name imported into the GSS-API library"),
    AP_INIT_FLAG("SPNEGOAuthSaveDelegatedCred",
		 ap_set_flag_slot,
		 (void *)APR_OFFSETOF(spnego_config, spnego_save_cred),
		 OR_AUTHCFG | RSRC_CONF,
		 "set to 'on' to save delegated gss-api authentication "
		 "(requires non standard API support from gssapi)"),

    AP_INIT_TAKE1("SPNEGOAuthKrb5AcceptorIdentity",
		  ap_set_string_slot,
		  (void *)APR_OFFSETOF(spnego_config, 
				       spnego_krb5_acceptor_identity),
		  OR_AUTHCFG | RSRC_CONF,
		  "set to Kerberos 5 keytab filename "
		  "(valid iff compiled with krb5 support)"),
    AP_INIT_FLAG("SPNEGOUseDisplayName",
		 ap_set_flag_slot,
		 (void *)APR_OFFSETOF(spnego_config, spnego_use_display_name),
		 OR_AUTHCFG | RSRC_CONF,
		 "set to 'on' to make SPNEGO use display name instead of "
		 "export name in REMOTE_USER"),
    { NULL }
};

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
	ap_table_set(r->subprocess_env, "KRB5CCNAME", fn);
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
access_checker(request_rec * r)
{
    const struct mech_specific *m;
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc in, out;
    gss_cred_id_t delegated_cred_handle;
    gss_name_t src_name = GSS_C_NO_NAME;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    spnego_config *c;
    const char *p, *q;
    char *user, *reply;
    gss_OID oid;
    int ret;

    c = ap_get_module_config(r->per_dir_config, &spnego_module);
    if (c == NULL || !c->spnego_on)
	return DECLINED;

    p = apr_table_get(r->headers_in, "Authorization");

    if (p == NULL) {
	ap_table_setn(r->err_headers_out, WWW_AUTHENTICATE, NEGOTIATE_NAME);
	return HTTP_UNAUTHORIZED;
    }

    q = ap_getword_white(r->pool, &p);
    if (q == NULL || strcmp(q, NEGOTIATE_NAME) != 0) {
	ap_table_setn(r->err_headers_out, WWW_AUTHENTICATE, NEGOTIATE_NAME);
	return HTTP_UNAUTHORIZED;
    }

    in.value = apr_palloc(r->pool, ap_base64decode_len(p));
    in.length = apr_base64decode_binary(in.value, p);

    out.length = 0;
    out.value = NULL;

    delegated_cred_handle = NULL;

#ifdef HAVE_KRB5
    if (c->spnego_krb5_acceptor_identity)
	gsskrb5_register_acceptor_identity(c->spnego_krb5_acceptor_identity);
#endif

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

    /* XXX */
    if ((maj_stat & GSS_S_CONTINUE_NEEDED) || maj_stat != GSS_S_COMPLETE) {
	OM_uint32 message_context = 0, min_stat2, ret;
	gss_buffer_desc error;
	
	ret = gss_display_status(&min_stat2,
				 min_stat, 
				 GSS_C_MECH_CODE, 
				 GSS_C_NO_OID,
				 &message_context,
				 &error);
	if (ret == 0)
	    apr_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			   "mod_spnego: accept_sec_context %d/%d: %s", 
			   maj_stat, min_stat, (char *)error.value);
	
	ret = HTTP_UNAUTHORIZED;
	goto out;
    }
				      
    if (c->spnego_use_display_name) {
	gss_buffer_desc name;

	maj_stat = gss_display_name(&min_stat, src_name, &name, NULL);
	if (maj_stat != GSS_S_COMPLETE) {
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
	    ret = HTTP_UNAUTHORIZED;
	    goto out;
	}
    
	user = apr_palloc(r->connection->pool, 
			  ap_base64encode_len(name.length));
	apr_base64encode(user, name.value, name.length);

	gss_release_buffer(&min_stat, &name);
    }
    r->user = user;
    r->ap_auth_type = apr_pstrdup(r->connection->pool, NEGOTIATE_NAME);

    ap_table_set(r->subprocess_env, "NEGOTIATE_INITIATOR_NAME", user);

    if (out.length) {
	size_t len;
	reply = apr_palloc(r->pool, ap_base64encode_len(out.length) + 2);
	reply[0] = ' ';
	len = apr_base64encode(reply + 1, out.value, out.length);
	reply[len + 1] = '\0';
    } else
	reply = "";
    
    ap_table_setn(r->headers_out, WWW_AUTHENTICATE,
		  apr_pstrcat(r->pool, NEGOTIATE_NAME, reply, NULL));

    ret = OK;

    if (delegated_cred_handle && c->spnego_save_cred) {
	m = find_mech(oid);
	if (m && m->save_cred)
	    (*m->save_cred)(r, delegated_cred_handle);
    }

 out:
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

static void
mod_spnego_register_hooks (apr_pool_t *p)
{
    ap_hook_check_user_id(access_checker, NULL, NULL, APR_HOOK_MIDDLE);
}


module AP_MODULE_DECLARE_DATA spnego_module =
{
  STANDARD20_MODULE_STUFF,
  NULL,
  NULL,
  NULL,
  NULL,
  spnego_cmds,
  mod_spnego_register_hooks
};
