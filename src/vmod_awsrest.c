#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
/* need vcl.h before vrt.h for vmod_evet_f typedef */
#include "cache/cache.h"
#include "vcl.h"

/* mhash need to be included after cache for avoiding re-define */
#include <mhash.h>

#ifndef VRT_H_INCLUDED
#include <vrt.h>
#endif

#ifndef VDEF_H_INCLUDED
#include <vdef.h>
#endif

#include "vtim.h"
#include "vcc_awsrest_if.h"

#if VRT_MAJOR_VERSION > 8U
int  vmod_event_function(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
#else
int  event_function(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
#endif
{
	return (0);
}

#define ALLOC_AND_STRNCPY(d, f, s) d = WS_Alloc(ctx->ws, s + 1); memset(d, '\0', s + 1); strncpy(d, f, s); 

static int compa(const void *a, const void *b)
{
    return strcmp(*(const char **)a, *(const char **)b);
}

bool isStartsWith(const char *prefix, const char *fullstr)
{
    return strncmp(prefix, fullstr, strlen(prefix)) == 0;
}

char * headersort(VRT_CTX, char *txt, char sep, char sfx)
{
    const char *cq, *cu;
    char *p, *r;
    const char **pp;
    const char **pe;
    unsigned u;
    int np;
    int i;

    CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

    if (txt == NULL)
        return (NULL);

    /* Split :query from :url */
    cu = txt;

    /* Spot single-param queries */
    cq = strchr(cu, sep);
    if (cq == NULL)
        return (txt);

    r = WS_Copy(ctx->ws, txt, strlen(txt) + 1);
    r[strlen(txt)] = '\0';
    if (r == NULL)
        return (txt);

    u = WS_ReserveLumps(ctx->ws, sizeof(const char **));
#if VRT_MAJOR_VERSION >= 12U
    pp = WS_Reservation(ctx->ws);
#else
    pp = (const char**)(void*)(ctx->ws->f);
#endif
    if (u < 4) {
        WS_Release(ctx->ws, 0);
        WS_MarkOverflow(ctx->ws);
        return (txt);
    }
    pe = pp + u;

    /* Collect params as pointer pairs */
    np = 0; // number of params
    pp[np++] =  cu;
    for (cq =  cu; *cq != '\0'; cq++) {
        if (*cq == sep) {
            if (pp + np + 3 > pe) {
                WS_Release(ctx->ws, 0);
                WS_MarkOverflow(ctx->ws);
                return (txt);
            }
            pp[np++] = cq;
            /* Skip trivially empty params */
            while (cq[1] == sep)
                cq++;
            pp[np++] = cq + 1;
        }
    }
    pp[np++] = cq;
    assert(!(np & 1));

    qsort(pp, np / 2, sizeof(*pp) * 2, compa);

    /* Emit sorted params */
    p =  r + (cu - txt);
    cq = "";
    for (i = 0; i < np; i += 2) {
        /* Ignore any edge-case zero length params */
        if (pp[i + 1] == pp[i])
            continue;
        assert(pp[i + 1] > pp[i]);
        if (*cq) *p++ = *cq;
        memcpy(p, pp[i], pp[i + 1] - pp[i]);
        p += pp[i + 1] - pp[i];
        cq = &sep;
    }

    if(sfx){
        *p = sfx;
        p++;
    }
    *p = '\0';

    WS_Release(ctx->ws, 0);
    return (r);
}


/////////////////////////////////////////////
static const char * vmod_hmac_sha256(VRT_CTX,
    const char *key, size_t lkey, const char *msg, size_t lmsg, bool raw)
{
    hashid hash = MHASH_SHA256;
    size_t blocksize = mhash_get_block_size(hash);

    char *p;
    char *ptmp;
    p    = WS_Alloc(ctx->ws, blocksize * 2 + 1);
    ptmp = p;

    unsigned char *mac;
    unsigned u;
#if VRT_MAJOR_VERSION > 9
    u = WS_ReserveAll(ctx->ws);
#else
    u = WS_Reserve(ctx->ws, 0);
#endif
    assert(u > blocksize);
    mac = (unsigned char*)ctx->ws->f;

    int i;
    MHASH td;

    assert(msg);
    assert(key);

    assert(mhash_get_hash_pblock(hash) > 0);

    td = mhash_hmac_init(hash, (void *) key, lkey,
            mhash_get_hash_pblock(hash));
    mhash(td, msg, lmsg);
    mhash_hmac_deinit(td,mac);
    if(raw){
        WS_Release(ctx->ws, blocksize);
        return (char *)mac;
    }
    WS_Release(ctx->ws, 0);

    for (i = 0; i<blocksize;i++) {
        sprintf(ptmp,"%.2x",mac[i]);
        ptmp+=2;
    }
    return p;
}

static const char * vmod_hash_sha256(VRT_CTX, const char *msg)
{
    MHASH td;
    hashid hash = MHASH_SHA256;
    unsigned char h[mhash_get_block_size(hash)];
    int i;
    char *p;
    char *ptmp;
    td = mhash_init(hash);
    mhash(td, msg, strlen(msg));
    mhash_deinit(td, h);
    p = WS_Alloc(ctx->ws, mhash_get_block_size(hash)*2 + 1);
    ptmp = p;
    for (i = 0; i < mhash_get_block_size(hash);i++) {
        sprintf(ptmp,"%.2x",h[i]);
        ptmp+=2;
    }
    return p;
}

/////////////////////////////////////////////
// Header Get
// copy from https://github.com/varnish/varnish-modules/blob/master/src/vmod_header.c
const struct gethdr_s hdr_null[HDR_BERESP + 1] = {
	[HDR_REQ]	= { HDR_REQ,		"\0"},
	[HDR_REQ_TOP]	= { HDR_REQ_TOP,	"\0"},
	[HDR_RESP]	= { HDR_RESP,		"\0"},
	[HDR_OBJ]	= { HDR_OBJ,		"\0"},
	[HDR_BEREQ]	= { HDR_BEREQ,		"\0"},
	[HDR_BERESP]	= { HDR_BERESP,	"\0"}
};

VCL_HEADER vmod_dyn(VRT_CTX, enum gethdr_e where, VCL_STRING name)
{
	char *what;
	const char *p;
	struct gethdr_s *hdr;
	size_t l;

	if (name == NULL || *name == '\0')
		return (&hdr_null[where]);

	p = strchr(name, ':');
	if (p != NULL)
		l = p - name;
	else
		l = strlen(name);

	assert(l <= CHAR_MAX);

	hdr = WS_Alloc(ctx->ws, sizeof *hdr);
	what = WS_Alloc(ctx->ws, l + 3);
	if (hdr == NULL || what == NULL) {
		VRT_fail(ctx, "out of workspace");
		// avoid null check in caller
		return (&hdr_null[where]);
	}

	what[0] = (char)l + 1;
	(void) strncpy(&what[1], name, l);
	what[l+1] = ':';
	what[l+2] = '\0';

	hdr->where = where;
	hdr->what = what;
	return (hdr);
}

/// @brief AWS V4 Signature
/// @param  
/// @param secret_key
/// @param dateStamp 
/// @param regionName 
/// @param serviceName 
/// @param string_to_sign 
/// @return 
static const char * vmod_v4_getSignature(VRT_CTX,
    const char* secret_key, const char* dateStamp, const char* regionName, const char* serviceName, const char* string_to_sign
){
    size_t len = strlen(secret_key) + 5;
    char key[len];
    char *kp = key;
    sprintf(kp,"AWS4%s",secret_key);

    const char *kDate    = vmod_hmac_sha256(ctx,kp,strlen(kp), dateStamp, strlen(dateStamp),true);
    const char *kRegion  = vmod_hmac_sha256(ctx,kDate,   32, regionName, strlen(regionName),true);
    const char *kService = vmod_hmac_sha256(ctx,kRegion, 32, serviceName, strlen(serviceName),true);
    const char *kSigning = vmod_hmac_sha256(ctx,kService,32, "aws4_request", 12,true);

    return vmod_hmac_sha256(ctx,kSigning,32, string_to_sign,strlen(string_to_sign),false);
}

////////////////////////////////////////////
VCL_STRING vmod_lf(VRT_CTX)
{
    char *p;
    p = WS_Alloc(ctx->ws,2);
    strcpy(p,"\n");
    return p;
}

char * formurl(VRT_CTX, char* url)
{
    char *adr, *ampadr, *eqadr;
    char *pp, *p;
    unsigned u;
    int len = 0;
    int cnt = 0;
    const char *lst= url + strlen(url) -1;

    adr = strchr(url, (int)'?');

    if(adr == NULL){
        return url;
    }

#if VRT_MAJOR_VERSION > 9
    u = WS_ReserveAll(ctx->ws);
#else
    u = WS_Reserve(ctx->ws, 0);
#endif
    pp = p = ctx->ws->f;

    len = adr - url;
    if(len + 1 > u){ // 1=(null)
        WS_Release(ctx->ws, 0);
        WS_MarkOverflow(ctx->ws);
        return url;
    }
    memcpy(p, url, len);
    p+=len;
    for(;lst >url;lst--){
        if(*lst != '?' && *lst != '&'){
            lst++;
            break;
        }
    }
    if(lst <= adr){
        // url: /xxxx? /?
        *p = 0;
        p++;
        WS_Release(ctx->ws, p - pp);
        return(pp);
    }

    while(1){
        ampadr = memchr(adr +1, (int)'&', lst - adr -1);
        if(ampadr == NULL){
            len = lst - adr;
            if(p - pp + len + 2 > u){ // 2= strlen("=")+1(null)
                WS_Release(ctx->ws, 0);
                WS_MarkOverflow(ctx->ws);
                return url;
            }
            memcpy(p, adr, len);
            p+=len;

            eqadr = memchr(adr +1, (int)'=', lst - adr -1);
            if(eqadr == NULL){
                cnt++;
                *p = '=';
                p++;
            }
            break;
        }else{
            eqadr = memchr(adr +1, (int)'=', ampadr - adr -1);
            len = ampadr - adr;
            if(p - pp + len + 2 > u){
                WS_Release(ctx->ws, 0);
                WS_MarkOverflow(ctx->ws);
                return url;
            }
            memcpy(p, adr, len);
            p+=len;
            if(eqadr == NULL){
                cnt++;
                *p = '=';
                p++;
            }
            adr = ampadr;
        }
    }
    *p = 0;
    p++;
    WS_Release(ctx->ws, p - pp);

    return(pp);

}

struct AWS_AUTH_ELEMENTS {
  char *credential;
  char *signedHeaders;
  char *signature;
  char *accessKey;
  char *datestamp;
  char *region;
  char *service;
  char *httpMethod;
  char *requestUri;
  char *queryString;
  char *contentPayloadHash;
  char *headerList;
};

struct AWS_AUTH_ELEMENTS init_auth_element() {
    struct AWS_AUTH_ELEMENTS init = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    return init;
}

void getAwsAuthElementFromAuthHeader (VRT_CTX,
    struct AWS_AUTH_ELEMENTS *authe,
    const char *current_auth
) {
    // split the current auth into auth elements
    char *splitToken;
    char* mutable_str = WS_Copy(ctx->ws, current_auth, strlen(current_auth) + 1);
    mutable_str[strlen(current_auth)] = '\0';

    splitToken = strtok(mutable_str, " ,");
    while (splitToken!= NULL) {
        if (isStartsWith("Credential=", splitToken)) { 
            int fixSize = 11;
            ALLOC_AND_STRNCPY(
                authe->credential, 
                splitToken + fixSize, 
                strlen(splitToken) - fixSize 
            );
        }
        if (isStartsWith("SignedHeaders=", splitToken)) {
            int fixSize = 14;
            ALLOC_AND_STRNCPY(
                authe->signedHeaders, 
                splitToken + fixSize, 
                strlen(splitToken) - fixSize
            );
        }
        if (isStartsWith("Signature=", splitToken)) {
            int fixSize = 10;
            ALLOC_AND_STRNCPY(
                authe->signature, 
                splitToken + fixSize, 
                strlen(splitToken) - fixSize
            );
        }
        splitToken = strtok(NULL, " ,");
    }

    // split credential to detail information
    mutable_str = WS_Copy(ctx->ws, authe->credential, strlen(authe->credential) + 1);
    mutable_str[strlen(authe->credential)] = '\0';

    splitToken = strtok(mutable_str, "/");
    int idx = 0;
    while (splitToken != NULL) {
        int allocSize = strlen(splitToken) + 1;
        if ( idx == 0) {
            ALLOC_AND_STRNCPY(authe->accessKey, splitToken, allocSize);
        }
        else if ( idx == 1) {
            ALLOC_AND_STRNCPY(authe->datestamp, splitToken, allocSize);
        }
        else if ( idx == 2) {
            ALLOC_AND_STRNCPY(authe->region, splitToken, allocSize);
        }
        else if ( idx == 3) {
            ALLOC_AND_STRNCPY(authe->service, splitToken, allocSize);
        }
        idx ++ ;
        splitToken = strtok(NULL, "/");
    }
}

void getAwsAuthElementFromHttp(VRT_CTX,
    struct AWS_AUTH_ELEMENTS *authe,
    struct http *http_req
) {
    const char *method = http_req->hd[HTTP_HDR_METHOD].b;
    int method_len = strlen(method);
    ALLOC_AND_STRNCPY( authe->httpMethod, method, method_len);

    const char *requrl = http_req->hd[HTTP_HDR_URL].b;
    char *adr = strchr(requrl, (int)'?');
    if(adr == NULL) {
        int size = strlen(requrl) + 1;
        ALLOC_AND_STRNCPY(authe->requestUri, requrl, size);
        ALLOC_AND_STRNCPY(authe->queryString, "", 1);
    }
    else{
        char* mutable_url = WS_Copy(ctx->ws, requrl, strlen(requrl) + 1);
        mutable_url[strlen(requrl)] = '\0';
        char* normalizedUrl = formurl(ctx, mutable_url);

        int total_len = strlen(normalizedUrl);
        char *x_adr = strchr(normalizedUrl, (int)'?');
        long url_len = x_adr - normalizedUrl;

        char tmpform[8];
        memset(tmpform, '\0', 8);
        sprintf(tmpform, "%s.%lds", "%", url_len);

        authe->requestUri = WS_Alloc(ctx->ws, url_len + 1);
        memset(authe->requestUri, '\0', url_len + 1);
        sprintf(authe->requestUri, tmpform, normalizedUrl);

        const char *qs = x_adr + 1;
        ALLOC_AND_STRNCPY(authe->queryString, qs, total_len - url_len + 1);
        authe->queryString = headersort(ctx, authe->queryString, '&', 0);
    }
}

void composeAwsAuthElementForHeaders(VRT_CTX,
    struct AWS_AUTH_ELEMENTS *authe,
    enum gethdr_e where
) {
    char* headerName;

    char* fullHeaderList = WS_Copy(ctx->ws, authe->signedHeaders, strlen(authe->signedHeaders) + 1);
    fullHeaderList[strlen(authe->signedHeaders)] = '\0';

    headerName = strtok(fullHeaderList, ";");
    int currentTotalLen = 0;
    while (headerName != NULL) {
        int len_headerName = strlen(headerName) ;
        const char *headerVal = VRT_GetHdr(ctx, vmod_dyn(ctx, where, headerName));
        int len_headerVal = strlen(headerVal);
        int currentHeaderLen = len_headerName + 1 + len_headerVal + 2 ; /* name:val \n */

        char* tmp_full = WS_Alloc(ctx->ws, currentTotalLen + currentHeaderLen + 1);
        memset(tmp_full, '\0', currentTotalLen + currentHeaderLen + 1);

        if (currentTotalLen == 0) {
            sprintf(tmp_full, "%s:%s\n", headerName, headerVal);
        } else {
            sprintf(tmp_full, "%s%s:%s\n", authe->headerList, headerName, headerVal);
        }
        currentTotalLen = currentTotalLen + currentHeaderLen;

        ALLOC_AND_STRNCPY(authe->headerList, tmp_full, currentTotalLen);

        headerName = strtok(NULL, ";");
    }
}


VCL_BOOL vmod_v4_validate(VRT_CTX, 
    VCL_STRING access_key,            //= 'your access key';
    VCL_STRING secret_key             //= 'your secret key';
) {
    struct http *http_req;
    enum gethdr_e where;

    if (ctx->http_bereq !=NULL && ctx->http_bereq->magic== HTTP_MAGIC){
        // bg-thread
        http_req = ctx->http_bereq;
        where = HDR_BEREQ;
    }else{
        // client-thread
        http_req = ctx->http_req;
        where = HDR_REQ;
    }

    struct AWS_AUTH_ELEMENTS elements = init_auth_element();

    const char *current_auth = VRT_GetHdr(ctx, vmod_dyn(ctx, where, "Authorization"));
    // the auth didn't start with aws auth prefix
    if ( ! isStartsWith("AWS4-HMAC-SHA256", current_auth) ) {
        return false;
    }

    getAwsAuthElementFromAuthHeader(ctx, &elements, current_auth );
    getAwsAuthElementFromHttp(ctx, &elements, http_req);
    composeAwsAuthElementForHeaders(ctx, &elements, where);

    const char *content_hash = VRT_GetHdr(ctx, vmod_dyn(ctx, where, "x-amz-content-sha256"));
    ALLOC_AND_STRNCPY(elements.contentPayloadHash, content_hash, 64);

    int totalSize = strlen(elements.httpMethod) + 2
                  + strlen(elements.requestUri) + 2
                  + strlen(elements.queryString) + 2
                  + strlen(elements.headerList) + 2
                  + strlen(elements.signedHeaders) + 2
                  + strlen(elements.contentPayloadHash);
    
    char *canonical_request = WS_Alloc(ctx->ws, totalSize + 1);
    memset(canonical_request, '\0', totalSize + 1);
    
    sprintf(canonical_request, "%s\n%s\n%s\n%s\n%s\n%s",
            elements.httpMethod, elements.requestUri, elements.queryString,
            elements.headerList, elements.signedHeaders, elements.contentPayloadHash);

    ////////////////
    // char *credential_req_temp = WS_Alloc(ctx->ws, totalSize + 1);
    // memset(credential_req_temp, '\0', totalSize + 1);
    // sprintf(credential_req_temp, "%s", elements.httpMethod);
    // VSLb(ctx->vsl, SLT_VCL_Log, "xxxx (1) => %s", vmod_hash_sha256(ctx, credential_req_temp));

    // sprintf(credential_req_temp, "%s\n%s", elements.httpMethod, elements.requestUri);
    // VSLb(ctx->vsl, SLT_VCL_Log, "xxxx (2) => %s", vmod_hash_sha256(ctx, credential_req_temp));

    // sprintf(credential_req_temp, "%s\n%s\n%s", elements.httpMethod, elements.requestUri, elements.queryString);
    // VSLb(ctx->vsl, SLT_VCL_Log, "xxxx (3) => %s %s", elements.queryString, vmod_hash_sha256(ctx, credential_req_temp));

    // sprintf(credential_req_temp, "%s\n%s\n%s\n%s", elements.httpMethod, elements.requestUri, elements.queryString, elements.headerList);
    // VSLb(ctx->vsl, SLT_VCL_Log, "xxxx (4) => %s", vmod_hash_sha256(ctx, credential_req_temp));

    // sprintf(credential_req_temp, "%s\n%s\n%s\n%s\n%s", elements.httpMethod, elements.requestUri, elements.queryString, elements.headerList, elements.signedHeaders);
    // VSLb(ctx->vsl, SLT_VCL_Log, "xxxx (5) => %s", vmod_hash_sha256(ctx, credential_req_temp));

    // sprintf(credential_req_temp, "%s\n%s\n%s\n%s\n%s\n%s", elements.httpMethod, elements.requestUri, elements.queryString, elements.headerList, elements.signedHeaders, elements.contentPayloadHash);
    // VSLb(ctx->vsl, SLT_VCL_Log, "xxxx (6) => %s", vmod_hash_sha256(ctx, credential_req_temp));

    ////////////////
    
    int len_credential_scope = strlen(elements.datestamp) + 1
                             + strlen(elements.region) + 1
                             + strlen(elements.service) + 1
                             + 12; /* aws4_request */

    char *credential_scope = WS_Alloc(ctx->ws, len_credential_scope + 1);
    memset(credential_scope, '\0', len_credential_scope + 1);
    sprintf(credential_scope, "%s/%s/%s/aws4_request",
            elements.datestamp, elements.region, elements.service);

    const char *amz_date = VRT_GetHdr(ctx, vmod_dyn(ctx, where, "x-amz-date"));
    int string_to_sign_len = 16 + 2  /* AWS4-HMAC-SHA256 */
                           + strlen(amz_date) + 2
                           + len_credential_scope + 2 
                           + 33;
    char *string_to_sign = WS_Alloc(ctx->ws, string_to_sign_len + 1);
    memset(string_to_sign, '\0', string_to_sign_len + 1);

    sprintf(string_to_sign, "AWS4-HMAC-SHA256\n%s\n%s\n%s", 
        amz_date,
        credential_scope,
        vmod_hash_sha256(ctx, canonical_request)
    );

    const char *signature = vmod_v4_getSignature(ctx, secret_key, 
        elements.datestamp, 
        elements.region,
        elements.service,
        string_to_sign);

    VSLb(ctx->vsl, SLT_VCL_Log, "signature => %s",  signature);
    int compareResult = strcmp(elements.signature, signature);
    if ( compareResult == 0 ) {
        return true;
    }
    else {
        return false;
    }
}

void vmod_v4_generic(VRT_CTX,
	VCL_STRING service,               //= 's3';
	VCL_STRING region,                //= 'ap-northeast-1';
	VCL_STRING access_key,            //= 'your access key';
	VCL_STRING secret_key,            //= 'your secret key';
	VCL_STRING token,                 //= 'optional session token';
	VCL_STRING signed_headers,       //= 'host;';// x-amz-content-sha256;x-amz-date is appended by default.
	VCL_STRING canonical_headers,    //= 'host:s3-ap-northeast-1.amazonaws.com\n'
	VCL_BOOL feature                  //= reserved param(for varnish4)
){
	////////////////
	//get data
	const char *method;
	const char *requrl;
	struct http *hp;
	struct gethdr_s gs;
	
	if (ctx->http_bereq !=NULL && ctx->http_bereq->magic== HTTP_MAGIC){
		//bg-thread
		hp = ctx->http_bereq;
		gs.where = HDR_BEREQ;
	}else{
		//cl-thread
		hp = ctx->http_req;
		gs.where = HDR_REQ;
	}
	method= hp->hd[HTTP_HDR_METHOD].b;
	requrl= hp->hd[HTTP_HDR_URL].b;

	////////////////
	//create date
	time_t tt;
	char amzdate[33];
	char datestamp[25];
	tt = time(NULL);
	struct tm * gmtm = gmtime(&tt);
	
	sprintf(amzdate,
		"%d%02d%02dT%02d%02d%02dZ",
		gmtm->tm_year +1900,
		gmtm->tm_mon  +1,
		gmtm->tm_mday,
		gmtm->tm_hour,
		gmtm->tm_min,
		gmtm->tm_sec
	);
	sprintf(datestamp,
		"%d%02d%02d",
		gmtm->tm_year +1900,
		gmtm->tm_mon  +1,
		gmtm->tm_mday
	);

	////////////////
	//create payload
	const char * payload_hash = vmod_hash_sha256(ctx, "");
	
	////////////////
	//create signed headers
	size_t tokenlen = 0;
	if(token != NULL) tokenlen = strlen(token);

	size_t len = strlen(signed_headers) + 32;
	if(tokenlen > 0) len += 21; // ;x-amz-security-token
	char *psh = WS_Alloc(ctx->ws,len);
	char *psigned_headers = WS_Alloc(ctx->ws,len);
	if(tokenlen > 0) {
		sprintf(psh,"%sx-amz-content-sha256;x-amz-date;x-amz-security-token",signed_headers);
	} else {
		sprintf(psh,"%sx-amz-content-sha256;x-amz-date",signed_headers);
	}
	psigned_headers = headersort(ctx, psh, ';', 0);
	////////////////
	//create canonical headers
	len = strlen(canonical_headers) + 115;
	// Account for addition of "x-amz-security-token:[token]\n"
	if(tokenlen > 0) len += 22 + tokenlen;
	char *pch = WS_Alloc(ctx->ws,len);
	char *pcanonical_headers = WS_Alloc(ctx->ws,len);

	if(tokenlen > 0) {
		sprintf(pch,"%sx-amz-content-sha256:%s\nx-amz-date:%s\nx-amz-security-token:%s\n",canonical_headers,payload_hash,amzdate,token);
	} else {
		sprintf(pch,"%sx-amz-content-sha256:%s\nx-amz-date:%s\n",canonical_headers,payload_hash,amzdate);
	}
	pcanonical_headers = headersort(ctx, pch, '\n', '\n');

	////////////////
	//create credential scope
	len = strlen(datestamp)+ strlen(region)+ strlen(service)+ 16;
	char *pcredential_scope = WS_Alloc(ctx->ws,len);
	sprintf(pcredential_scope,"%s/%s/%s/aws4_request",datestamp,region,service);
	
	////////////////
	//create canonical request
	len = strlen(method)+ strlen(requrl)+ strlen(pcanonical_headers)+ strlen(psigned_headers)+ strlen(payload_hash) + 6;
	char *pcanonical_request = WS_Alloc(ctx->ws,len);
	char tmpform[32];
	tmpform[0]=0;
	char *ptmpform = &tmpform[0];

	char *adr = strchr(requrl, (int)'?');
	if(adr == NULL){
		sprintf(pcanonical_request,"%s\n%s\n\n%s\n%s\n%s",
			method,
			requrl,
			pcanonical_headers,
			psigned_headers,
			payload_hash
		);
	}else{
		sprintf(ptmpform,"%s.%lds\n%s","%s\n%",(adr - requrl),"%s\n%s\n%s\n%s");
		sprintf(pcanonical_request,ptmpform,
			method,
			requrl,
			adr + 1,
			pcanonical_headers,
			psigned_headers,
			payload_hash
		);
	}
	
	
	////////////////
	//create string_to_sign
	len = strlen(amzdate)+ strlen(pcredential_scope)+ 33;
	char *pstring_to_sign = WS_Alloc(ctx->ws,len);
	sprintf(pstring_to_sign,"AWS4-HMAC-SHA256\n%s\n%s\n%s",amzdate,pcredential_scope,vmod_hash_sha256(ctx, pcanonical_request));
	
	////////////////
	//create signature
	const char *signature = vmod_v4_getSignature(ctx,secret_key,datestamp,region,service,pstring_to_sign);

	////////////////
	//create authorization
	len = strlen(access_key)+ strlen(pcredential_scope)+ strlen(psigned_headers)+ strlen(signature)+ 58;
	char *pauthorization= WS_Alloc(ctx->ws,len);
	
	sprintf(pauthorization,"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		access_key,
		pcredential_scope,
		psigned_headers,
		signature);
	
#if VRT_MAJOR_VERSION >= 14U
        ////////////////
        //Set to header
        gs.what = "\016Authorization:";
        VRT_SetHdr(ctx, &gs        , pauthorization , NULL);
        gs.what = "\025x-amz-content-sha256:";
        VRT_SetHdr(ctx, &gs , payload_hash , NULL);
        gs.what = "\013x-amz-date:";
        VRT_SetHdr(ctx, &gs           , amzdate , NULL);
        if(tokenlen > 0){
          gs.what="\025x-amz-security-token:";
          VRT_SetHdr(ctx, &gs, token, NULL);
        }
#else
        ////////////////
        //Set to header
        gs.what = "\016Authorization:";
        VRT_SetHdr(ctx, &gs        , pauthorization , vrt_magic_string_end);
        gs.what = "\025x-amz-content-sha256:";
        VRT_SetHdr(ctx, &gs , payload_hash , vrt_magic_string_end);
        gs.what = "\013x-amz-date:";
        VRT_SetHdr(ctx, &gs           , amzdate , vrt_magic_string_end);
        if(tokenlen > 0){
          gs.what="\025x-amz-security-token:";
          VRT_SetHdr(ctx, &gs, token, vrt_magic_string_end);
        }
#endif
}