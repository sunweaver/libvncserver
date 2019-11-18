/*
 * rfbcrypto_gnutls.c - Crypto wrapper (GnuTLS version)
 *
 *  Copyright (C) 2019 Christian Beier <dontmind@sdf.org>
 *
 *  This is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This software is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this software; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 *  USA.
 */

#include <string.h>
#include <gnutls/crypto.h>
#include "rfbcrypto.h"

#if LIBVNCSERVER_HAVE_SYS_UIO_H

void digestmd5(const struct iovec *iov, int iovcnt, void *dest)
{
    gnutls_hash_hd_t c;
    int i;

    gnutls_hash_init(&c, GNUTLS_DIG_MD5);
    for (i = 0; i < iovcnt; i++)
	gnutls_hash(c, iov[i].iov_base, iov[i].iov_len);

    gnutls_hash_deinit(c, dest);
}

void digestsha1(const struct iovec *iov, int iovcnt, void *dest)
{
    gnutls_hash_hd_t c;
    int i;

    gnutls_hash_init(&c, GNUTLS_DIG_SHA1);
    for (i = 0; i < iovcnt; i++)
	gnutls_hash(c, iov[i].iov_base, iov[i].iov_len);

    gnutls_hash_deinit(c, dest);
}

#endif
