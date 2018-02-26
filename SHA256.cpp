#include "StdAfx.h"
#include "SHA256.h"


SHA256::SHA256(void)
{
    Reset();
}


SHA256::~SHA256(void)
{
}

inline unsigned int SHA256::Ch(unsigned int x, unsigned int y, unsigned int z)
{
    return z ^ (x & (y ^ z));
}

inline unsigned int SHA256::Maj(unsigned int x, unsigned int y, unsigned int z)
{
    //return (x & y) | (z & (x | y));
    return (x & y) ^ (x & z) ^ (y & z);
}

inline unsigned int SHA256::Sigma0(unsigned int x)
{
    return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10);
}

inline unsigned int SHA256::Sigma1(unsigned int x)
{
    return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7);
}

inline unsigned int SHA256::sigma0(unsigned int x)
{
    return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3);
}

inline unsigned int SHA256::sigma1(unsigned int x)
{
    return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10);
}

void SHA256::Reset(void)
{
    m_BufLen = 0;
    m_Bytes = 0;
    m_Hash[0] = 0x6a09e667;
    m_Hash[1] = 0xbb67ae85;
    m_Hash[2] = 0x3c6ef372;
    m_Hash[3] = 0xa54ff53a;
    m_Hash[4] = 0x510e527f;
    m_Hash[5] = 0x9b05688c;
    m_Hash[6] = 0x1f83d9ab;
    m_Hash[7] = 0x5be0cd19;
}

/** One round of SHA-256. */
inline void SHA256::Round(unsigned int a, unsigned int b, unsigned int c, unsigned int& d, unsigned int e, unsigned int f, unsigned int g, unsigned int& h, unsigned int k, unsigned int w)
{
    unsigned int t1 = h + Sigma1(e) + Ch(e, f, g) + k + w;
    unsigned int t2 = Sigma0(a) + Maj(a, b, c);

    d += t1;
    h = t1 + t2;
}

inline unsigned int SHA256::ReadBE32(const unsigned char* buf)
{
    // change to big-endian
    return (unsigned int)buf[0] << 24 | (unsigned int)buf[1] << 16 | (unsigned int)buf[2] << 8 | buf[3];
}

inline void SHA256::WriteBE32(unsigned char* buf, unsigned int val)
{
    // change to big-endian
    *(unsigned int*)buf = ((val & 0x000000FF) << 24) | ((val & 0x0000FF00) << 8) | ((val & 0x00FF0000) >> 8) | ((val & 0xFF000000) >> 24);
}

inline void SHA256::WriteBE64(unsigned char* buf, unsigned long long val)
{
    // change to big-endian
    unsigned long long t;

    t = (((val & 0xff00000000000000ull) >> 56)
       | ((val & 0x00ff000000000000ull) >> 40)
       | ((val & 0x0000ff0000000000ull) >> 24)
       | ((val & 0x000000ff00000000ull) >> 8)
       | ((val & 0x00000000ff000000ull) << 8)
       | ((val & 0x0000000000ff0000ull) << 24)
       | ((val & 0x000000000000ff00ull) << 40)
       | ((val & 0x00000000000000ffull) << 56));
    memcpy(buf, (char*)&t, 8);
}

void SHA256::Transform(const unsigned char* chunk, unsigned int blocks)
{
    unsigned int a = m_Hash[0], b = m_Hash[1], c = m_Hash[2], d = m_Hash[3], e = m_Hash[4], f = m_Hash[5], g = m_Hash[6], h = m_Hash[7];
    unsigned int w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

    while(blocks--)
    {
        Round(a, b, c, d, e, f, g, h, 0x428a2f98, w0 = ReadBE32(chunk + 0));
        Round(h, a, b, c, d, e, f, g, 0x71374491, w1 = ReadBE32(chunk + 4));
        Round(g, h, a, b, c, d, e, f, 0xb5c0fbcf, w2 = ReadBE32(chunk + 8));
        Round(f, g, h, a, b, c, d, e, 0xe9b5dba5, w3 = ReadBE32(chunk + 12));
        Round(e, f, g, h, a, b, c, d, 0x3956c25b, w4 = ReadBE32(chunk + 16));
        Round(d, e, f, g, h, a, b, c, 0x59f111f1, w5 = ReadBE32(chunk + 20));
        Round(c, d, e, f, g, h, a, b, 0x923f82a4, w6 = ReadBE32(chunk + 24));
        Round(b, c, d, e, f, g, h, a, 0xab1c5ed5, w7 = ReadBE32(chunk + 28));
        Round(a, b, c, d, e, f, g, h, 0xd807aa98, w8 = ReadBE32(chunk + 32));
        Round(h, a, b, c, d, e, f, g, 0x12835b01, w9 = ReadBE32(chunk + 36));
        Round(g, h, a, b, c, d, e, f, 0x243185be, w10 = ReadBE32(chunk + 40));
        Round(f, g, h, a, b, c, d, e, 0x550c7dc3, w11 = ReadBE32(chunk + 44));
        Round(e, f, g, h, a, b, c, d, 0x72be5d74, w12 = ReadBE32(chunk + 48));
        Round(d, e, f, g, h, a, b, c, 0x80deb1fe, w13 = ReadBE32(chunk + 52));
        Round(c, d, e, f, g, h, a, b, 0x9bdc06a7, w14 = ReadBE32(chunk + 56));
        Round(b, c, d, e, f, g, h, a, 0xc19bf174, w15 = ReadBE32(chunk + 60));

        Round(a, b, c, d, e, f, g, h, 0xe49b69c1, w0 += sigma1(w14) + w9 + sigma0(w1));
        Round(h, a, b, c, d, e, f, g, 0xefbe4786, w1 += sigma1(w15) + w10 + sigma0(w2));
        Round(g, h, a, b, c, d, e, f, 0x0fc19dc6, w2 += sigma1(w0) + w11 + sigma0(w3));
        Round(f, g, h, a, b, c, d, e, 0x240ca1cc, w3 += sigma1(w1) + w12 + sigma0(w4));
        Round(e, f, g, h, a, b, c, d, 0x2de92c6f, w4 += sigma1(w2) + w13 + sigma0(w5));
        Round(d, e, f, g, h, a, b, c, 0x4a7484aa, w5 += sigma1(w3) + w14 + sigma0(w6));
        Round(c, d, e, f, g, h, a, b, 0x5cb0a9dc, w6 += sigma1(w4) + w15 + sigma0(w7));
        Round(b, c, d, e, f, g, h, a, 0x76f988da, w7 += sigma1(w5) + w0 + sigma0(w8));
        Round(a, b, c, d, e, f, g, h, 0x983e5152, w8 += sigma1(w6) + w1 + sigma0(w9));
        Round(h, a, b, c, d, e, f, g, 0xa831c66d, w9 += sigma1(w7) + w2 + sigma0(w10));
        Round(g, h, a, b, c, d, e, f, 0xb00327c8, w10 += sigma1(w8) + w3 + sigma0(w11));
        Round(f, g, h, a, b, c, d, e, 0xbf597fc7, w11 += sigma1(w9) + w4 + sigma0(w12));
        Round(e, f, g, h, a, b, c, d, 0xc6e00bf3, w12 += sigma1(w10) + w5 + sigma0(w13));
        Round(d, e, f, g, h, a, b, c, 0xd5a79147, w13 += sigma1(w11) + w6 + sigma0(w14));
        Round(c, d, e, f, g, h, a, b, 0x06ca6351, w14 += sigma1(w12) + w7 + sigma0(w15));
        Round(b, c, d, e, f, g, h, a, 0x14292967, w15 += sigma1(w13) + w8 + sigma0(w0));

        Round(a, b, c, d, e, f, g, h, 0x27b70a85, w0 += sigma1(w14) + w9 + sigma0(w1));
        Round(h, a, b, c, d, e, f, g, 0x2e1b2138, w1 += sigma1(w15) + w10 + sigma0(w2));
        Round(g, h, a, b, c, d, e, f, 0x4d2c6dfc, w2 += sigma1(w0) + w11 + sigma0(w3));
        Round(f, g, h, a, b, c, d, e, 0x53380d13, w3 += sigma1(w1) + w12 + sigma0(w4));
        Round(e, f, g, h, a, b, c, d, 0x650a7354, w4 += sigma1(w2) + w13 + sigma0(w5));
        Round(d, e, f, g, h, a, b, c, 0x766a0abb, w5 += sigma1(w3) + w14 + sigma0(w6));
        Round(c, d, e, f, g, h, a, b, 0x81c2c92e, w6 += sigma1(w4) + w15 + sigma0(w7));
        Round(b, c, d, e, f, g, h, a, 0x92722c85, w7 += sigma1(w5) + w0 + sigma0(w8));
        Round(a, b, c, d, e, f, g, h, 0xa2bfe8a1, w8 += sigma1(w6) + w1 + sigma0(w9));
        Round(h, a, b, c, d, e, f, g, 0xa81a664b, w9 += sigma1(w7) + w2 + sigma0(w10));
        Round(g, h, a, b, c, d, e, f, 0xc24b8b70, w10 += sigma1(w8) + w3 + sigma0(w11));
        Round(f, g, h, a, b, c, d, e, 0xc76c51a3, w11 += sigma1(w9) + w4 + sigma0(w12));
        Round(e, f, g, h, a, b, c, d, 0xd192e819, w12 += sigma1(w10) + w5 + sigma0(w13));
        Round(d, e, f, g, h, a, b, c, 0xd6990624, w13 += sigma1(w11) + w6 + sigma0(w14));
        Round(c, d, e, f, g, h, a, b, 0xf40e3585, w14 += sigma1(w12) + w7 + sigma0(w15));
        Round(b, c, d, e, f, g, h, a, 0x106aa070, w15 += sigma1(w13) + w8 + sigma0(w0));

        Round(a, b, c, d, e, f, g, h, 0x19a4c116, w0 += sigma1(w14) + w9 + sigma0(w1));
        Round(h, a, b, c, d, e, f, g, 0x1e376c08, w1 += sigma1(w15) + w10 + sigma0(w2));
        Round(g, h, a, b, c, d, e, f, 0x2748774c, w2 += sigma1(w0) + w11 + sigma0(w3));
        Round(f, g, h, a, b, c, d, e, 0x34b0bcb5, w3 += sigma1(w1) + w12 + sigma0(w4));
        Round(e, f, g, h, a, b, c, d, 0x391c0cb3, w4 += sigma1(w2) + w13 + sigma0(w5));
        Round(d, e, f, g, h, a, b, c, 0x4ed8aa4a, w5 += sigma1(w3) + w14 + sigma0(w6));
        Round(c, d, e, f, g, h, a, b, 0x5b9cca4f, w6 += sigma1(w4) + w15 + sigma0(w7));
        Round(b, c, d, e, f, g, h, a, 0x682e6ff3, w7 += sigma1(w5) + w0 + sigma0(w8));
        Round(a, b, c, d, e, f, g, h, 0x748f82ee, w8 += sigma1(w6) + w1 + sigma0(w9));
        Round(h, a, b, c, d, e, f, g, 0x78a5636f, w9 += sigma1(w7) + w2 + sigma0(w10));
        Round(g, h, a, b, c, d, e, f, 0x84c87814, w10 += sigma1(w8) + w3 + sigma0(w11));
        Round(f, g, h, a, b, c, d, e, 0x8cc70208, w11 += sigma1(w9) + w4 + sigma0(w12));
        Round(e, f, g, h, a, b, c, d, 0x90befffa, w12 += sigma1(w10) + w5 + sigma0(w13));
        Round(d, e, f, g, h, a, b, c, 0xa4506ceb, w13 += sigma1(w11) + w6 + sigma0(w14));
        Round(c, d, e, f, g, h, a, b, 0xbef9a3f7, w14 + sigma1(w12) + w7 + sigma0(w15));
        Round(b, c, d, e, f, g, h, a, 0xc67178f2, w15 + sigma1(w13) + w8 + sigma0(w0));

        m_Hash[0] += a;
        m_Hash[1] += b;
        m_Hash[2] += c;
        m_Hash[3] += d;
        m_Hash[4] += e;
        m_Hash[5] += f;
        m_Hash[6] += g;
        m_Hash[7] += h;
        chunk += 64;
    }
}

void SHA256::Update(const unsigned char* data, unsigned int len)
{
    if(m_BufLen && m_BufLen + len >= 64)
    {
        // Fill the buffer, and process it.
        memcpy(m_Buf + m_BufLen, data, 64 - m_BufLen);
        m_Bytes += 64 - m_BufLen;
        data += 64 - m_BufLen;
        len -= 64 - m_BufLen;
        Transform(m_Buf, 1);
        m_BufLen = 0;
    }
    if(len >= 64)
    {
        unsigned int blocks = len / 64;
        len = len % 64;
        Transform(data, blocks);
        data += 64 * blocks;
        m_Bytes += 64 * blocks;
    }
    if(len != 0)
    {
         // Fill the buffer with what remains.
        memcpy(m_Buf + m_BufLen, data, len);
        m_BufLen += len;
        m_Bytes += len;
    }
}

void SHA256::Finalize(unsigned char hash[32])
{
    static const unsigned char pad[64] = {0x80};
    unsigned char size[8];

    WriteBE64(size, m_Bytes << 3);
    Update(pad, 1 + (64 * 2 - 1 - 8 - m_BufLen) % 64);
    Update(size, 8);
    WriteBE32(hash + 0, m_Hash[0]);
    WriteBE32(hash + 4, m_Hash[1]);
    WriteBE32(hash + 8, m_Hash[2]);
    WriteBE32(hash + 12, m_Hash[3]);
    WriteBE32(hash + 16, m_Hash[4]);
    WriteBE32(hash + 20, m_Hash[5]);
    WriteBE32(hash + 24, m_Hash[6]);
    WriteBE32(hash + 28, m_Hash[7]);
}
