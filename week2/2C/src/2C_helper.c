#include "2C/2C_helper.h"

BIO *bio_in = NULL;
BIO *bio_out = NULL;
BIO *bio_err = NULL;

int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value)
{
    int rv;
    char *stmp, *vtmp = NULL;
    stmp = OPENSSL_strdup(value);
    if (!stmp)
        return -1;
    vtmp = strchr(stmp, ':');
    if (vtmp) {
        *vtmp = 0;
        vtmp++;
    }
    rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);
    OPENSSL_free(stmp);
    return rv;
}


int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey,
                        const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts)
{
    EVP_PKEY_CTX *pkctx = NULL;
    int i, def_nid, ret = 0;

    if (ctx == NULL)
        goto err;
    /*
     * EVP_PKEY_get_default_digest_nid() returns 2 if the digest is mandatory
     * for this algorithm.
     */
    if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) == 2
            && def_nid == NID_undef) {
        /* The signing algorithm requires there to be no digest */
        md = NULL;
    }
    if (!EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey))
        goto err;
    for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++) {
        char *sigopt = sk_OPENSSL_STRING_value(sigopts, i);
        if (pkey_ctrl_string(pkctx, sigopt) <= 0) {
            BIO_printf(bio_err, "parameter error \"%s\"\n", sigopt);
            ERR_print_errors(bio_err);
            goto err;
        }
    }

    ret = 1;
 err:
    return ret;
}


int do_X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts)
{
    int rv;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();

    rv = do_sign_init(mctx, pkey, md, sigopts);
    if (rv > 0) {
        rv = X509_REQ_sign_ctx(x, mctx);
    }
    EVP_MD_CTX_free(mctx);
    return rv > 0 ? 1 : 0;
}

/*
 * name is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */
X509_NAME *parse_name(const char *cp, long chtype, int canmulti)
{
    int nextismulti = 0;
    char *work;
    X509_NAME *n;

    if (*cp++ != '/') {
        BIO_printf(bio_err,
                   "name is expected to be in the format "
                   "/type0=value0/type1=value1/type2=... where characters may "
                   "be escaped by \\. This name is not in that format: '%s'\n",
                   --cp);
        return NULL;
    }

    n = X509_NAME_new();
    if (n == NULL)
        return NULL;
    work = OPENSSL_strdup(cp);
    if (work == NULL) {
        /* BIO_printf(bio_err, "%s: Error copying name input\n", opt_getprog()); */
        goto err;
    }

    while (*cp) {
        char *bp = work;
        char *typestr = bp;
        unsigned char *valstr;
        int nid;
        int ismulti = nextismulti;
        nextismulti = 0;

        /* Collect the type */
        while (*cp && *cp != '=')
            *bp++ = *cp++;
        if (*cp == '\0') {
            /* BIO_printf(bio_err, */
            /*         "%s: Hit end of string before finding the '='\n", */
            /*         opt_getprog()); */
            goto err;
        }
        *bp++ = '\0';
        ++cp;

        /* Collect the value. */
        valstr = (unsigned char *)bp;
        for (; *cp && *cp != '/'; *bp++ = *cp++) {
            if (canmulti && *cp == '+') {
                nextismulti = 1;
                break;
            }
            if (*cp == '\\' && *++cp == '\0') {
                /* BIO_printf(bio_err, */
                /*            "%s: escape character at end of string\n", */
                /*            opt_getprog()); */
                goto err;
            }
        }
        *bp++ = '\0';

        /* If not at EOS (must be + or /), move forward. */
        if (*cp)
            ++cp;

        /* Parse */
        nid = OBJ_txt2nid(typestr);
        if (nid == NID_undef) {
            /* BIO_printf(bio_err, "%s: Skipping unknown attribute \"%s\"\n", */
            /*            opt_getprog(), typestr); */
            continue;
        }
        if (*valstr == '\0') {
            /* BIO_printf(bio_err, */
            /*            "%s: No value provided for Subject Attribute %s, skipped\n", */
            /*            opt_getprog(), typestr); */
            continue;
        }
        if (!X509_NAME_add_entry_by_NID(n, nid, chtype,
                                        valstr, strlen((char *)valstr),
                                        -1, ismulti ? -1 : 0)) {
            /* BIO_printf(bio_err, "%s: Error adding name attribute \"/%s=%s\"\n", */
            /*            opt_getprog(), typestr ,valstr); */
            goto err;
        }
    }

    OPENSSL_free(work);
    return n;

 err:
    X509_NAME_free(n);
    OPENSSL_free(work);
    return NULL;
}


/*
 * subject is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */
static int build_subject(X509_REQ *req, const char *subject, unsigned long chtype,
                         int multirdn)
{
    X509_NAME *n;

    if ((n = parse_name(subject, chtype, multirdn)) == NULL)
        return 0;

    if (!X509_REQ_set_subject_name(req, n)) {
        X509_NAME_free(n);
        return 0;
    }
    X509_NAME_free(n);
    return 1;
}

int make_REQ(X509_REQ *req, EVP_PKEY *pkey, char *subj, int multirdn,
                    int attribs, unsigned long chtype)
{
    int ret = 0, i;

    /* setup version number */
    if (!X509_REQ_set_version(req, 0L))
        goto err;               /* version 1 */

    i = build_subject(req, subj, chtype, multirdn);

    if (!X509_REQ_set_pubkey(req, pkey))
        goto err;

    ret = 1;
 err:
    return ret;
}
