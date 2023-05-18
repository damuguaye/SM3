#include<iostream>
#include<sstream>
#include "sm3.hpp"

using namespace std;

int main(){
    
    string str = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    SM3 sm;
    cout<<sm.hash(str)<<endl;  
    str = "abc";
    cout<<sm.hash(str)<<endl;  


    system("pause");
}