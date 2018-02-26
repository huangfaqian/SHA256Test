#pragma once
class SHA256
{
protected:
    unsigned int m_Hash[8]; // hash
    unsigned char m_Buf[64]; // data buffer
    unsigned int m_BufLen; // data lenth in buffer
    unsigned long long m_Bytes; // data bytes
public:
    SHA256(void);
    ~SHA256(void);
    // inline
    unsigned int Ch(unsigned int x, unsigned int y, unsigned int z);
    unsigned int Maj(unsigned int x, unsigned int y, unsigned int z);
    unsigned int Sigma0(unsigned int x);
    unsigned int Sigma1(unsigned int x);
    unsigned int sigma0(unsigned int x);
    unsigned int sigma1(unsigned int x);
    void Reset(void);
    void Round(unsigned int a, unsigned int b, unsigned int c, unsigned int& d, unsigned int e, unsigned int f, unsigned int g, unsigned int& h, unsigned int k, unsigned int w);
    void Transform(const unsigned char* chunk, unsigned int blocks);
    unsigned int ReadBE32(const unsigned char* buf);
    void WriteBE32(unsigned char* buf, unsigned int val);
    void WriteBE64(unsigned char* buf, unsigned long long val);
    void Update(const unsigned char* data, unsigned int len);
    void Finalize(unsigned char hash[32]);
};

