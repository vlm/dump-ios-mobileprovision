#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include "SignedXML.h"

int main(int ac, char **av) {
    size_t filesize, fread_nitems;
    FILE *f;
    char *buf;
    SignedXML_t *container = 0;
    asn_dec_rval_t rv;

    if(ac != 2) {
        fprintf(stderr, "Usage: %s <filename.mobileprovision>\n", av[0]);
        exit(1);
    }

    /* Open the file */
    f = fopen(av[1], "rb");
    if(!f) {
        fprintf(stderr, "Can't open %s: %s\n", av[1], strerror(errno));
        exit(1);
    }

    /* Determine the file's length */
    fseek(f, 0, SEEK_END);
    filesize = ftell(f);
    fseek(f, 0, SEEK_SET);

    /* Allocate memory and read-in file */
    buf = malloc(filesize);
    assert(buf);
    fread_nitems = fread(buf, filesize, 1, f);
    assert(fread_nitems == 1);

    /* Grok the file */
    rv = ber_decode(0, &asn_DEF_SignedXML, (void **)&container, buf, filesize);
    free(buf);

    switch(rv.code) {
    case RC_OK:
        break;
    case RC_FAIL:
        fprintf(stderr, "%s: wrong file format\n", av[1]);
        exit(1);
    case RC_WMORE:
        fprintf(stderr, "%s: truncated file\n", av[1]);
        exit(1);
    }

    /* Sanity-check the PKCS#7, make sure it is SignedData */
    {
    int oid1[7], oid1_test[7] = {1,2,840,113549,1,7,2};
    int oid2[7], oid2_test[7] = {1,2,840,113549,1,7,1};
    int ret;
    ret = OBJECT_IDENTIFIER_get_arcs(&container->contentType,
        oid1, sizeof(oid1[0]), sizeof(oid1)/sizeof(oid1[0]));
      assert(ret == 7);
      assert(memcmp(oid1, oid1_test, sizeof(oid1)) == 0);
    assert(container->content.version == 1);
    ret = OBJECT_IDENTIFIER_get_arcs(&container->content.contentInfo.contentType,
        oid2, sizeof(oid2[0]), sizeof(oid2)/sizeof(oid2[0]));
      assert(ret == 7);
      assert(memcmp(oid2, oid2_test, sizeof(oid2)) == 0);
    }

    {
    OCTET_STRING_t *xml;
    xml = &container->content.contentInfo.contentXML;
    fwrite(xml->buf, xml->size, 1, stdout);
    }

    return 0;
}
