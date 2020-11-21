#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#define BLEN 16
#define ROWS 4
#define COLUMNS 3
#define CLASSES 2

LweSample* cypher_array[ROWS][COLUMNS];
LweSample* classes[COLUMNS];

int main(){
	//generate a keyset
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    printf("Starting process...\n");

    FILE* fp = fopen("precompute.txt", "r");
    printf("File opened\n");
    int i, j, k;
    for(i=0; i<CLASSES; i++){
    	int a;
    	classes[i] = new_gate_bootstrapping_ciphertext_array(BLEN,params);
    	fscanf(fp, "%d", &a);
    	for(k=0; k<BLEN; k++)
    		bootsSymEncrypt(&classes[i][k],(a>>k)&1,key);
    }
    for(i=0; i<ROWS; i++){
    	for(j=0; j<COLUMNS; j++){
    		int a;
    		fscanf(fp, "%d", &a);
    		cypher_array[i][j] = new_gate_bootstrapping_ciphertext_array(BLEN,params);
    		for(k=0; k<BLEN; k++)
    			bootsSymEncrypt(&cypher_array[i][j][k],(a>>k)&1,key);
    	}
    }
    fclose(fp);
    printf("File fucked\n");

    //export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    //export precomputations to cloud
	FILE* cloud_data=fopen("cloud.data","wb");
	for(i=0; i<CLASSES; i++)
		for(k=0; k<BLEN; k++)
			export_gate_bootstrapping_ciphertext_toFile(cloud_data, &classes[i][k],params);
	for(i=0; i<ROWS; i++)
    	for(j=0; j<COLUMNS; j++)
    		for(k=0; k<BLEN; k++)
    			export_gate_bootstrapping_ciphertext_toFile(cloud_data, &cypher_array[i][j][k],params);
    fclose(cloud_data);

    //clean up all pointer
    for(i=0; i<CLASSES; i++)
		delete_gate_bootstrapping_ciphertext_array(BLEN,classes[i]);
    for(i=0; i<ROWS; i++)
    	for(j=0; j<COLUMNS; j++)
    		delete_gate_bootstrapping_ciphertext_array(BLEN,cypher_array[i][j]);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
}