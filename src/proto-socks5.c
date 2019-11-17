#include "proto-banner1.h"
#include "unusedparm.h"
#include "masscan-app.h"
#include "proto-interactive.h"
#include <ctype.h>

static void
abort_session(struct InteractiveData *more, unsigned *state) {
    *state = 0xffffffff;
    tcp_close(more);
}

static void
socks5_parse(const struct Banner1 *banner1,
             void *banner1_private,
             struct ProtocolState *pstate,
             const unsigned char *px, size_t length,
             struct BannerOutput *banout,
             struct InteractiveData *more) {

    unsigned state = pstate->state;
    unsigned i;

    UNUSEDPARM(banner1_private);
    UNUSEDPARM(banner1);

    for (i = 0; i < length; i++) {

        switch (state) {
            case 0:
            case 2:
                if (px[i] != 0x05) {
                    abort_session(more, &state);
                }
                state++;
                break;
            case 1:
                if (px[i] != 0x00) {
                    abort_session(more, &state);
                }
                tcp_transmit(more, "\x05\x01\x00\x03\x0agoogle.com\x00\x50", 17, 0);
                state++;
                break;
            case 3:abort_session(more, &state);
                banout_append_char(banout, PROTO_SOCKS5, px[i]);
                /* fall through */
            default:i = (unsigned) length;
                break;
        }
    }
    pstate->state = state;
}

static void *
socks5_init(struct Banner1 *banner1) {
    UNUSEDPARM(banner1);
    return 0;
}

static int
socks5_selftest(void) {
    return 0;
}

static const char socks5_hello_message[] = "\x05\x01\x00";

const struct ProtocolParserStream banner_socks5 = {
    "socks5", 1080, socks5_hello_message, 3, 0,
    socks5_selftest,
    socks5_init,
    socks5_parse,
};
