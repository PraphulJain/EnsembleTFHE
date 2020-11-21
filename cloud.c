#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>
#define BLEN 16
#define ROWS 4
#define COLUMNS 3
#define CLASSES 2

void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* temp1=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp2=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp3=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    LweSample* temp4=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    LweSample* temp5=new_gate_bootstrapping_ciphertext_array(1,bk->params);

    bootsXOR(temp1, a, b, bk);  //a xorb
    bootsXOR(result,temp1,lsb_carry,bk);  //a xor b xor ci
    
    bootsNOT(temp4,a,bk);  // complement of a
    bootsAND(temp3,temp4,b,bk); // complement a and b

    bootsNOT(temp5,temp1,bk);  // complement of a XOR b

    bootsAND(temp2,temp5,lsb_carry,bk);// complement of a XOR b AND lasb_carry
  
    bootsOR(tmp,temp2,temp3,bk);       // a&b + ci*(a xor b)
    bootsCOPY(lsb_carry,tmp,bk);
}

void subtract(LweSample* result, LweSample* tmps, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    //run the elementary comparator gate n times//
      
    for (int i=0; i<nb_bits; i++){
        compare_bit(&result[i], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    }
}

void Addition(LweSample* top1, const LweSample* a6, const LweSample* b6, LweSample* lsb_carry1, LweSample* tmp6, const  TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* temp1=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp2=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp3=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    
    bootsXOR(temp1, a6, b6, bk);  //a xor b  
    bootsXOR(top1,temp1,lsb_carry1,bk);  //a xor b xor ci
    bootsAND(temp2,temp1,lsb_carry1,bk);   //ci and (a xor b)
    bootsAND(temp3,a6,b6,bk);             // a and b 
    bootsOR(tmp6,temp2,temp3,bk);       // a&b + ci*(a xor b)
    bootsCOPY(lsb_carry1,tmp6,bk);


}
void Adder(LweSample* top1, const LweSample* a6, const LweSample* b6, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk){
    LweSample* tmps6 = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    bootsCONSTANT(&tmps6[0], 0, bk); //initialize carry to 0

    //run the elementary comparator gate n times//
        
    for (int i=0; i<nb_bits; i++){
        Addition(&top1[i], &a6[i], &b6[i], &tmps6[0], &tmps6[1], bk);
    }
    delete_gate_bootstrapping_ciphertext_array(2, tmps6);    
}

void multiplexer(LweSample* rdbdata,LweSample* a,LweSample* b,LweSample* select_line,const int nb_bit, const TFheGateBootstrappingCloudKeySet* bk){
    int m=0;
    for(int i=0;i<nb_bit;i++){
        bootsMUX(&rdbdata[i],&select_line[m],&b[i],&a[i],bk);
    }
}

void multiply(LweSample* product, LweSample* a, LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk){
        
    LweSample* enc_theta=new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    for(int i=0;i<nb_bits;i++){ //initialize theta to all zero bits
        bootsCONSTANT(&enc_theta[i],0,bk);
    }
    for(int i=0;i<2*nb_bits;i++){ //initialize product to all zero bits
        bootsCONSTANT(&product[i],0,bk);
    } 

    for (int i=0; i<nb_bits; i++) {
        LweSample* temp_result=new_gate_bootstrapping_ciphertext_array(2 * nb_bits, bk->params);
        LweSample* partial_sum=new_gate_bootstrapping_ciphertext_array(2 * nb_bits, bk->params);
        for(int j=0;j<2*nb_bits;j++){ //initialize temp_result to all zero bits
            bootsCONSTANT(&temp_result[j],0,bk);
            bootsCONSTANT(&partial_sum[j],0,bk);
        } 
        LweSample* temp2=new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
        multiplexer(temp2,enc_theta,a,&b[i],nb_bits,bk);
        for(int j=0;j<nb_bits;j++){ 
            bootsCOPY(&temp_result[i+j],&temp2[j],bk);
        }

        //Add the valid result to partial_sum//
        Adder(partial_sum,product,temp_result,2*nb_bits,bk);
        //Change the partial sum to final product//
        for(int j=0;j<2*nb_bits;j++){ 
            bootsCOPY(&product[j],&partial_sum[j],bk);
        }
    }
}

void is_equal(LweSample* equal, LweSample* a, LweSample* b, const int n_bits, const TFheGateBootstrappingCloudKeySet* bk){
    int i;
    LweSample* temp1 = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp3 = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    bootsCONSTANT(&equal[0],0,bk);
    bootsCONSTANT(temp2,0,bk);
    for(i=0; i<n_bits; i++){
        bootsXOR(temp1, &a[i], &b[i], bk);
        bootsOR(temp3, temp2, temp1, bk);
        bootsCOPY(temp2, temp3, bk);
        bootsNOT(&equal[0], temp3, bk);
    }
}

struct structure{
    LweSample* class_name;
    LweSample* frequency;
};

LweSample* cypher[ROWS][COLUMNS];
struct structure details[CLASSES];

void main(){
    printf("Reading the key...\n");

    //Reading the cloud key from file
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);
 
    //Params are inside the key
    const TFheGateBootstrappingParameterSet* params = bk->params;

    //Reading the cloud data (precomputations) and the query data
    printf("Reading the ciphertexts...\n");
    FILE* cloud_data = fopen("cloud.data","rb");
    int i, j, k;
    for(i=0; i<CLASSES; i++){
        details[i].class_name = new_gate_bootstrapping_ciphertext_array(BLEN,params);
        details[i].frequency = new_gate_bootstrapping_ciphertext_array(BLEN,params);
        for(k=0; k<BLEN; k++){
            import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &details[i].class_name[k], params);
            bootsCONSTANT(&details[i].frequency[k], 0, bk);
        }
    }
    for(i=0; i<ROWS; i++){
        for(j=0; j<COLUMNS; j++){
            cypher[i][j] = new_gate_bootstrapping_ciphertext_array(BLEN,params);
            for(k=0; k<BLEN; k++)
                import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &cypher[i][j][k], params);
        }
    }
    fclose(cloud_data);

    //temprory variables
    LweSample* max_class = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    LweSample* max_boobs = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    LweSample* compare = new_gate_bootstrapping_ciphertext_array(2, params);
    LweSample* equal = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    LweSample* booty = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    LweSample* temp = new_gate_bootstrapping_ciphertext_array(BLEN, params);

    for(k=0; k<BLEN; k++){
        bootsCONSTANT(&max_class[k], 0, bk);
        bootsCONSTANT(&max_boobs[k], 0, bk);
        bootsCONSTANT(&equal[k], 0, bk);
        bootsCONSTANT(&temp[k], 0, bk);
    }

    int test_case = 3;

    time_t start_time = clock();
    //First loop for updating frequencies of every class
    for(i=0; i<COLUMNS; i++){
        for(j=0; j<CLASSES; j++){
            bootsCONSTANT(&equal[0], 0, bk);
            bootsCONSTANT(&equal[1], 0, bk);
            is_equal(equal, details[j].class_name, cypher[test_case][i], BLEN, bk);
            Adder(temp, details[j].frequency, equal, BLEN, bk);
            for(k=0; k<BLEN; k++){
                bootsCOPY(&details[j].frequency[k], &temp[k], bk);
                bootsCONSTANT(&temp[k], 0, bk);
            }
        }
    }

    //Second loop for finding the max frequency class
    for(i=0; i<CLASSES; i++){
        bootsCONSTANT(&compare[0], 0, bk);
        subtract(booty, compare, details[i].frequency, max_boobs, BLEN, bk);
        multiplexer(max_class, details[i].class_name, max_class, compare, BLEN, bk);
        multiplexer(max_boobs, details[i].frequency, max_boobs, compare, BLEN, bk);
    }
    time_t end_time = clock();

    ///////////////////////////////Verification (Decryption)
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
    int int_answer=0;
    int base = 1;
    for(k=0; k<BLEN; k++){
        int ai = bootsSymDecrypt(&max_class[k], key)>0;
        int_answer += base*ai;
        base = base * 2;
        //int_answer |= (ai<<i);
    }
    printf("Result = %d \n", int_answer);
    //////////////////////////////
    printf("Executed successfully! Time to execute %ld second\n",(end_time-start_time)/1000000);

    //export the answer to a file (for the cloud)
    FILE* answer_data = fopen("answer.data","wb");
    for(k=0; k<BLEN; k++)
        export_gate_bootstrapping_ciphertext_toFile(answer_data, &max_class[k],params);
    fclose(answer_data);

    //delete_gate_bootstrapping_ciphertext_array(BLEN,ciphertext[i].ciphertext1);
    for(i=0; i<ROWS; i++)
        for(j=0; j<COLUMNS; j++)
            delete_gate_bootstrapping_ciphertext_array(BLEN,cypher[i][j]);

    delete_gate_bootstrapping_ciphertext_array(BLEN, booty);
    delete_gate_bootstrapping_ciphertext_array(BLEN, max_boobs);
    delete_gate_bootstrapping_ciphertext_array(BLEN, max_class);
    delete_gate_bootstrapping_ciphertext_array(2, compare);
    delete_gate_bootstrapping_ciphertext_array(BLEN, equal);
    delete_gate_bootstrapping_ciphertext_array(BLEN, temp);
}