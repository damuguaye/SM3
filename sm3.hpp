#ifndef SM3_HPP
#define SM3_HPP

#include<iostream>
#include<sstream>

#define SM3_RESULT_BIT 256
#define SM3_RESULT_UINT32 8 // SM3_RESULT_BIT / 32

#define SM3_BLOCK_BIT 512
#define SM3_BLOCK_UINT8 64 // SM3_BLOCK_BIT / 8
#define SM3_BLOCK_UINT32 16 // SM3_BLOCK_UINT8 / 4

#define SM3_EXTEND_W1 68
//#define SM3_EXTEND_W2 64
#define SM3_WORD_CNT 132

#define SM3_REST_BIT 448
#define SM3_REST_UINT8 56 // SM3_REST_BIT / 8


#define SM3_CHAR_BIT 8
#define SM3_UINT32_CHAR 4 // 32 / 8


class SM3{
public:
    SM3();
    std::string hash(std::istream &in);
    std::string hash(std::string &s);
    
private:
    void Init();

    void resetABCDEFGH();
    void resetV();
    void updateV();
    void complementW();
    void caculateOnce();
    uint32_t rotl_uint_32(uint32_t x, int n);
    uint32_t T(int j);
    uint32_t P0(uint32_t x);
    uint32_t P1(uint32_t x);
    uint32_t CF(uint32_t v, uint32_t b);
    uint32_t FF(uint32_t a, uint32_t b, uint32_t c, int j);
    uint32_t GG(uint32_t e, uint32_t f, uint32_t g, int j);
    uint32_t P0_TT2();
    uint32_t FF_ABC(int j);
    uint32_t GG_EFG(int j);
    
    std::string getStrResult();

    uint32_t W[SM3_WORD_CNT];

    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1;
    uint32_t SS2;
    uint32_t TT1;
    uint32_t TT2;
    uint32_t V[8];

    

    

};


void SM3::resetV(){
    V[0] = 0x7380166f;
    V[1] = 0x4914b2b9;
    V[2] = 0x172442d7;
    V[3] = 0xda8a0600;
    V[4] = 0xa96f30bc;
    V[5] = 0x163138aa;
    V[6] = 0xe38dee4d;
    V[7] = 0xb0fb0e4e;
}
void SM3::resetABCDEFGH(){
    A = V[0];
    B = V[1];
    C = V[2];
    D = V[3];
    E = V[4];
    F = V[5];
    G = V[6];
    H = V[7];
}

void SM3::updateV(){
    V[0] = A ^ V[0];
    V[1] = B ^ V[1];
    V[2] = C ^ V[2];
    V[3] = D ^ V[3];
    V[4] = E ^ V[4];
    V[5] = F ^ V[5];
    V[6] = G ^ V[6];
    V[7] = H ^ V[7];
}
void SM3::Init(){
    resetV();
}
SM3::SM3(){
    Init();
}

uint32_t SM3::rotl_uint_32(uint32_t x, int n){
    return (x << n) | (x >> (32 - n));
}

void SM3::complementW(){
    for(int i = SM3_BLOCK_UINT32; i < SM3_EXTEND_W1; ++i){
        W[i] = P1(W[i-16] ^ W[i-9] ^ rotl_uint_32(W[i-3], 15)) ^ rotl_uint_32(W[i-13], 7) ^ W[i-6];
    }
    
    for(int i = SM3_EXTEND_W1; i < SM3_WORD_CNT; ++i){
        W[i] = W[i - SM3_EXTEND_W1] ^ W[i - SM3_EXTEND_W1 + 4];
    }
}

uint32_t SM3::T(int j){ 
        return j < 16 ? 0x79cc4519: 0x7a879d8a;
}
uint32_t SM3::FF(uint32_t a, uint32_t b, uint32_t c, int j){
    if(j < 16){
        return a ^ b ^ c;
    }else{
        return (a & b) | (a & c) | (b & c);
    }
}

uint32_t SM3::GG(uint32_t e, uint32_t f, uint32_t g, int j){
    if(j < 16){
        return e ^ f ^ g;
    }else{
        return (e & f) | (~e & g);
    }
}

uint32_t SM3::P0(uint32_t x){
    return x ^ rotl_uint_32(x, 9) ^ rotl_uint_32(x, 17);
}

uint32_t SM3::P1(uint32_t x){
    return x ^ rotl_uint_32(x, 15) ^ rotl_uint_32(x, 23);
}

void SM3::caculateOnce(){
    //resetV();
    complementW();

    resetABCDEFGH();
    for(int i = 0; i < 64; ++i){
        SS1 = rotl_uint_32((rotl_uint_32(A, 12) + E + rotl_uint_32(T(i), i)), 7);
        SS2 = SS1 ^ rotl_uint_32(A, 12);
        TT1 = FF(A, B, C, i) + D + SS2 + W[i + SM3_EXTEND_W1];
        TT2 = GG(E, F, G, i) + H + SS1 + W[i];
        D = C;
        C = rotl_uint_32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = rotl_uint_32(F, 19);
        F = E;
        E = P0(TT2);
        
    }
    updateV();

}

std::string SM3::getStrResult(){
    std::stringstream ret;
    for(int i = 0; i < SM3_RESULT_UINT32; ++i){
        ret << std::hex << V[i];
    }
    return ret.str();

}
std::string SM3::hash(std::istream &in){

    uint64_t priLen = 0; //数据原始长度
    uint64_t compLen; //填充后长度
    //uint32_t pieces;
    char c;
    int Wcount = 0;
    uint32_t tmp = 0;
    Init();

    while(in.get(c)){
        ++priLen;
        tmp |= c;
        if(priLen % SM3_UINT32_CHAR){
            tmp <<= SM3_CHAR_BIT;
        }else{
            W[Wcount++] = tmp;
            tmp = 0;
            if(Wcount == SM3_BLOCK_UINT32){
                
                caculateOnce();
                Wcount = 0;
            }

        }

    }
    ++priLen;
    tmp |= 0x80;
    if(priLen % SM3_UINT32_CHAR){
        tmp <<= ((SM3_UINT32_CHAR - (priLen % SM3_UINT32_CHAR)) * SM3_CHAR_BIT);
    }
    W[Wcount++] = tmp;
    if(Wcount == SM3_BLOCK_UINT32){
       
        caculateOnce();
        Wcount = 0;
    }
    uint64_t count = priLen;
    if(count % SM3_UINT32_CHAR){
        count += SM3_UINT32_CHAR - (priLen % SM3_UINT32_CHAR);
    }
    --priLen;
    uint64_t remainder = count % SM3_BLOCK_UINT8;
    compLen = remainder > SM3_REST_UINT8 ? 
        (count - remainder + 2 * SM3_BLOCK_UINT8) :
        (count - remainder + SM3_BLOCK_UINT8);
    for(; count < compLen - SM3_BLOCK_UINT8 + SM3_REST_UINT8; count += SM3_UINT32_CHAR){
        W[Wcount++] = 0;
        if(Wcount == SM3_BLOCK_UINT32){
       
            caculateOnce();
            Wcount = 0;
        }
    }
    priLen *= SM3_CHAR_BIT;
    W[Wcount++] = (priLen >> 32) & 0xFFFFFFFF;
    W[Wcount] = priLen & 0xFFFFFFFF;

    caculateOnce();

    return getStrResult();
}


std::string SM3::hash(std::string &s){
    std::stringstream ss;
    ss << s;
    return hash(ss);
}

#endif