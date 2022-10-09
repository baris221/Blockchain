#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../rsa/rsaH.h"
#include "../primal/primalH.h"
#include "../key/keyH.h"
#include "../signature/signatureH.h"
#include "../protected/protectedH.h"


Protected* init_protected(Key* pKey, char* mess, Signature* sgn)
{
	Protected* newProtected = (Protected*) malloc(sizeof(Protected));
	if (!newProtected)
	{
		printf("[Init_Protected Function] Erreur Malloc\n");
		return NULL;
	}

	newProtected->pKey = pKey;
	newProtected->mess = strdup(mess);
	newProtected->sgn = sgn;

	return newProtected;
}

int verify(Protected* pr)
{
	if (!pr)
	{
		printf("[Verify Function] Erreur pr is NULL\n");
		return 0;
	}
	
	char* decryptedMsg = decrypt(pr->sgn->content, pr->sgn->size, pr->pKey->val, pr->pKey->n);

	if (strcmp(pr->mess, decryptedMsg) == 0)
	{
		delete_string(decryptedMsg);
		return 1;
	}

	delete_string(decryptedMsg);
	return 0;
}

char* protected_to_str(Protected* pr)
{
	if (!pr)
	{
		printf("[protected_to_str Function] Erreur pr is NULL\n");
		return 0;
	}

	char* keyStr = key_to_str(pr->pKey);

	char* messStr = pr->mess;

	char* sgnStr = signature_to_str(pr->sgn);

	int totalLen = strlen(keyStr) + strlen(messStr) + strlen(sgnStr) + 2 + 1;//2 => 2 espaces, 1 => '\0' 

	char* newString = (char*) malloc(sizeof(char) * totalLen);

	strcpy(newString, keyStr); //Copy init string
	strcat(newString, " "); //Concat the rest
	strcat(newString, messStr);
	strcat(newString, " ");
	strcat(newString, sgnStr);

	delete_string(keyStr);
	delete_string(sgnStr);

	return newString;
}


Protected* str_to_protected(char* protected_str)
{
	if (!protected_str)
	{
		printf("[Str_To_Protected Function] Erreur protected_str is NULL\n");
		return NULL;
	}

	long value, n;
	char mess[256];
	char sgn[256];

	sscanf(protected_str, "(%lx,%lx) %s %s", &value, &n, mess, sgn);

	Key* newKey = (Key*) malloc(sizeof(Key));
	if (!newKey)
	{
		printf("[Str_To_Protected Function] Erreur Malloc newKey\n");
		return NULL;
	}
	init_key(newKey, value, n);

	Signature* newSgnFromStr = str_to_signature(sgn);

	Protected* newProtected = (Protected*) malloc(sizeof(Protected));
	if (!newProtected)
	{
		printf("[Str_To_Protected Function] Erreur Malloc newProtected\n");
		return NULL;
	}

	newProtected->pKey = newKey;
	newProtected->mess = strdup(mess);
	newProtected->sgn = newSgnFromStr;

	return newProtected;
}


void delete_protected(Protected* pr)
{
	if (!pr)
	{
		printf("[delete_protected Function] Erreur pr is NULL\n");
		return;
	}

	if (pr->pKey)
		delete_key(pr->pKey);
	
	if (pr->sgn)
		delete_signature(pr->sgn);

	if (pr->mess)
		delete_string(pr->mess);

	free(pr);
	return;
}




int exists(char* key, char** tab_key_str, int size) 
{
	for (int i = 0; i < size; ++i)
	{
		if (tab_key_str[i])
		{
			if (strcmp(tab_key_str[i], key) == 0)
			{
				return 1;
			}
		}
	}

	return 0;
}


void generate_random_data(int nv, int nc)
{
	if (nv < 0 || nc < 0)
	{
		printf("[generate_random_data Function] Erreur nv OU nc < 0\n");
		return;
	}

	if (nc > nv)
	{
		printf("[generate_random_data Function] Erreur nc doit être < que nv\n");
		return;
	}

	FILE *f1 = fopen("keys.txt","w");
	FILE *f2 = fopen("candidates.txt","w");
	FILE *f3 = fopen("declarations.txt","w");

	Key* newPKey = (Key*) malloc(sizeof(Key));
	Key* newSKey = (Key*) malloc(sizeof(Key));
	
	char** tableDesClesCitoyens = (char**) malloc(nv * sizeof(char*));
	for (int i = 0; i < nv; i++)
		tableDesClesCitoyens[i] = NULL;

	char** tableDesClesSecretesCitoyens = (char**) malloc(nv * sizeof(char*));
	for (int i = 0; i < nv; i++)
		tableDesClesSecretesCitoyens[i] = NULL;
	
	//Génération clés publique/secrète unique pour nv citoyens
	int size = 0;
	for (int i = 0; i < nv; i++)
	{
		init_pair_keys(newPKey, newSKey, 3, 7);
		char* citoyenStringPKey = key_to_str(newPKey);
		char* citoyenStringSKey = key_to_str(newSKey);

		while (exists(citoyenStringPKey, tableDesClesCitoyens, size) == 1)
		{
			char* oldKey = key_to_str(newPKey);

			init_pair_keys(newPKey, newSKey, 3, 7);
			delete_string(citoyenStringPKey);
			citoyenStringPKey = key_to_str(newPKey);

			char* newKey = key_to_str(newPKey);
			printf("Clé publique de citoyen déjà présente: \nAncienne clé: %s \nNouvelle clé: %s\n", oldKey, newKey);

			delete_string(newKey);
			delete_string(oldKey);
		}
		
		tableDesClesCitoyens[i] = strdup(citoyenStringPKey);
		size++;

		tableDesClesSecretesCitoyens[i] = strdup(citoyenStringSKey);
		
		fprintf(f1,"%s %s\n", citoyenStringPKey, citoyenStringSKey);
		delete_string(citoyenStringPKey);
		delete_string(citoyenStringSKey);

		printf("\e[1;1H\e[2J"); //Clear Console
		printf("[generate_random_data Function] Génération en cours des clés publiques/secrète pour chaque citoyen...\n(%d/%d)\n", i, nv);
	}

	int indexTableClesCandidates = 0;
	char** tableDesClesCandidates = (char**) malloc(nc * sizeof(char*));
	for (int i = 0; i < nc; i++)
		tableDesClesCandidates[i] = NULL;

	//Sélection de nc clés publiques (toutes différentes) pour définir les nc candidats parmis les nv citoyens
	for(int j = 0; j < nc; j++)
	{
		int random = (rand() % nv);

		while (exists(tableDesClesCitoyens[random], tableDesClesCandidates, nc) == 1) //Tant que cette case n'est pas nulle on en cherche une autre...
		{
			printf("Already got this candidates, assign new one\n");
			random = rand() % nv;
		}

		//Candidat choisi d'index random <=> Citoyen d'index random
		tableDesClesCandidates[indexTableClesCandidates] = strdup(tableDesClesCitoyens[random]);

		//Maj du fichier
		fprintf(f2, "%s\n", tableDesClesCandidates[indexTableClesCandidates]);

		indexTableClesCandidates++;
	}


	//Génération des déclarations pour chaque citoyen
	for (int i = 0; i < nv; i++)
	{	
		Key* clePubliqueCitoyen = str_to_key(tableDesClesCitoyens[i]);
		Key* cleSecreteCitoyen = str_to_key(tableDesClesSecretesCitoyens[i]);

		int candidatRandom = rand() % nc;

		Key* clePubliqueCandidat = str_to_key(tableDesClesCandidates[candidatRandom]); //"Son nom" (tableDesClesCandidates[candidatRandom])

		Signature* sgn = sign(tableDesClesCandidates[candidatRandom], cleSecreteCitoyen);

		Protected* pr = init_protected(clePubliqueCitoyen, tableDesClesCandidates[candidatRandom], sgn);

		char* prCitoyen = protected_to_str(pr);

		fprintf(f3, "%s\n", prCitoyen);


		char* pKeyPr = key_to_str(pr->pKey);
		if (verify(pr) == 0)
		{
			printf("Vérification de mess: %s, de pKey: %s, est valide? %s\n", pr->mess, pKeyPr, "Non");
		}
		//printf("Vérification de mess: %s, de pKey: %s, est valide? %s\n", pr->mess, pKeyPr, verify(pr) ? "Oui" : "Non");
		delete_string(pKeyPr);

		//delete_key(clePubliqueCitoyen);
		delete_key(cleSecreteCitoyen);
		delete_key(clePubliqueCandidat);

		delete_protected(pr);

		delete_string(prCitoyen);
	}
	
	for(int candidatIndex = 0; candidatIndex < nc; candidatIndex++){
		free(tableDesClesCandidates[candidatIndex]);
	}
	free(tableDesClesCandidates);
	
	for(int citoyenIndex = 0; citoyenIndex < nv; citoyenIndex++){
		free(tableDesClesCitoyens[citoyenIndex]);
	}
	free(tableDesClesCitoyens);

	for(int citoyenSecreteIndex = 0; citoyenSecreteIndex < nv; citoyenSecreteIndex++){
		free(tableDesClesSecretesCitoyens[citoyenSecreteIndex]);
	}
	free(tableDesClesSecretesCitoyens);

	delete_key(newPKey);
	delete_key(newSKey);

	fclose(f1);
	fclose(f2);
	fclose(f3);
}