#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/sha.h>

#include "./rsa/rsaH.h"
#include "./primal/primalH.h"
#include "./key/keyH.h"
#include "./signature/signatureH.h"
#include "./protected/protectedH.h"
#include "./cellkey/cellkeyH.h"
#include "./cellprotected/cellprotectedH.h"
#include "./hashtable/hashtableH.h"
#include "./blockchain_code/blockchainH.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define NB_CITOYENS 1000 //Nombre de citoyens
#define NB_CANDIDATS 5 //Nombre de candidats à l'élection
#define NB_BITS 2 //Nombre de zéros requis pour validé par bruteforce le HASH

int main(void)
{
 	srand(time(NULL));

 	fprintf(stdout, "\n"ANSI_COLOR_GREEN"Lancement"ANSI_COLOR_RESET" d'une "ANSI_COLOR_YELLOW"génération"ANSI_COLOR_RESET" de clés publiques/privées pour "ANSI_COLOR_GREEN"%d"ANSI_COLOR_RESET" Citoyen(s) et "ANSI_COLOR_GREEN"%d"ANSI_COLOR_RESET" Candidat(s)\n", NB_CITOYENS, NB_CANDIDATS);
 	sleep(2);

 	generate_random_data(NB_CITOYENS, NB_CANDIDATS);

 	fprintf(stdout, "\n\nLa génération est "ANSI_COLOR_GREEN"terminée"ANSI_COLOR_RESET" pour "ANSI_COLOR_GREEN"%d"ANSI_COLOR_RESET" Citoyen(s) et "ANSI_COLOR_GREEN"%d"ANSI_COLOR_RESET" Candidat(s)\n", NB_CITOYENS,NB_CANDIDATS);
 	sleep(2);

    fprintf(stdout, "\n"ANSI_COLOR_GREEN"Lecture"ANSI_COLOR_RESET" des fichiers 'candidates.txt', 'keys.txt' et 'declarations.txt'\n");
    sleep(2);
    CellKey *candidates = read_public_keys("candidates.txt");
    CellKey *publicKeys = read_public_keys("keys.txt");
    CellProtected *votes = read_protected("declarations.txt");

    fprintf(stdout, "\n"ANSI_COLOR_GREEN"Lecture"ANSI_COLOR_RESET" des fichiers 'candidates.txt', 'keys.txt' et 'declarations.txt' "ANSI_COLOR_GREEN"terminée"ANSI_COLOR_RESET"\n");
    sleep(2);

    //soumission de tous les votes et rajout dans l'arbre
    fprintf(stdout, "\n"ANSI_COLOR_GREEN"Soumission"ANSI_COLOR_RESET" des votes avec génération d'un block tous les 10 votes soumis\n");
    sleep(2);

    CellTree *tree = NULL;  

    int i, nbFichier = 1, votesParBlock = 10;
    char nomFichier[256];
    CellProtected *current = votes;
    Protected *pr;
    Key *cleAssesseur = NULL;

    while (current)   
    {
        //On copie la cle de l'assesseur afin de pouvoir liberer completement le block et la liste de cles plus tard
        cleAssesseur = copie_key(current->data->pKey); //la cle de l'assesseur est la cle du premier a voter dans le block
        
        //On cree Pending_votes.txt en soumettant le bon nombre de votes
        i = 0;
        while (current && i<votesParBlock)
        {
            pr = current->data;
            submit_vote(pr);
            current = current->next;
            i++;
        }

        char* strKey = key_to_str(cleAssesseur);
        create_block(&tree, cleAssesseur, NB_BITS); //On cree un block a partir de Pending_votes.txt, puis on ecrit le block dans Pending_block.txt
        sprintf(nomFichier, strKey);
        add_block(NB_BITS, nomFichier); //On ajoute le contenu du fichier Pending_block.txt au repertoire Blockchain
        nbFichier++;

        delete_string(strKey);

        fprintf(stdout, "\e[1;1H\e[2J"); //Clear Console
		fprintf(stdout, ANSI_COLOR_GREEN"Ajout"ANSI_COLOR_RESET" des blocks à la blockchain...\n(%d/%d)\n", nbFichier, (NB_CITOYENS/votesParBlock)+1);
    }

    fprintf(stdout, "\n"ANSI_COLOR_GREEN"Ajout"ANSI_COLOR_RESET" des blocks "ANSI_COLOR_GREEN"terminée"ANSI_COLOR_RESET"\n");
    sleep(2);

    //Ayant enregistre les fichiers dans Blockchain on peut supprimer l'arbre de construction
    fprintf(stdout, "\n"ANSI_COLOR_GREEN"Affichage"ANSI_COLOR_RESET" de l'arbre correspondant\n");
    sleep(2);

    print_tree(tree);
    delete_tree(tree);

    //Lecture du repertoire Blockchain, re-creation et affichage de l'arbre
    tree = read_tree();
    fprintf(stdout, "\n"ANSI_COLOR_GREEN"Affichage"ANSI_COLOR_RESET" de l'arbre provenant du répertoire ./Blockchain/\n");
    sleep(2);
    print_tree(tree);
  	

    //Determination du gagnant
    fprintf(stdout, "\n"ANSI_COLOR_GREEN"Détermination"ANSI_COLOR_RESET" du vainqueur de l'élection\n");
    sleep(2);

    Key *gagnant = compute_winner_BT(tree, candidates, publicKeys, NB_CANDIDATS*2, NB_CITOYENS*2);

    char *g = key_to_str(gagnant);
    printf("\n\nLe "ANSI_COLOR_GREEN"vainqueur"ANSI_COLOR_RESET" de l'élection est %s\n\n", g);
    delete_string(g);

    delete_key(gagnant);
    delete_tree(tree);
    delete_list_protected(votes);
    delete_list_keys(candidates);
    delete_list_keys(publicKeys);

 	return 0;
}

//Ancien main() utilisé pour tester toutes les fonctions
/*
 	printf("\n\n\n"ANSI_COLOR_GREEN"Test"ANSI_COLOR_RESET" d'une génération aléatoire réprésentant 1 citoyen aléatoire...\n\n");

 	sleep(2);

 	//Testing Init Keys
 	Key* pKey = malloc(sizeof(Key));
 	Key* sKey = malloc(sizeof(Key));
 	init_pair_keys(pKey, sKey, 3, 7);
 	printf("pKey : %lx, %lx\n", pKey->val, pKey->n);
 	printf("sKey : %lx, %lx\n", sKey->val, sKey->n);

 	//Testing Key Serialization
 	char* chaine = key_to_str(pKey);
 	printf("key_to_str: %s\n", chaine);

 	Key* k = str_to_key(chaine);
	printf("str_to_key: %lx, %lx\n", k->val, k->n);

	//Testing signature
	//Candidate keys:
 	Key* pKeyC = malloc(sizeof(Key));
 	Key* sKeyC = malloc(sizeof(Key));
 	init_pair_keys(pKeyC, sKeyC, 3, 7);

 	//Declaration:
 	char* mess = key_to_str(pKeyC);
 	char* pKeyStr = key_to_str(pKeyC);
 	printf("%s vote pour %s\n", pKeyStr, mess);
 	Signature* sgn = sign(mess, sKey);
 	printf("Signature: ");
 	print_long_vector(sgn->content, sgn->size);

 	delete_string(chaine);
 	chaine = signature_to_str(sgn);

 	printf("signature_to_str: %s\n", chaine);

	delete_signature(sgn);
 	sgn = str_to_signature(chaine);

 	printf("str_to_signature: ");
 	print_long_vector(sgn->content, sgn->size);


 	//Testing protected:
 	Protected* pr = init_protected(pKey, mess, sgn);
 	//Verification:
 	if (verify(pr)) 
 	{
 		printf("\nSignature "ANSI_COLOR_GREEN"valide"ANSI_COLOR_RESET" !\n\n") ;
 	} else {
 		printf("\nSignature "ANSI_COLOR_RED"non valide"ANSI_COLOR_RESET" !\n\n") ;
	}

	delete_string(chaine);
 	chaine = protected_to_str(pr);

 	printf("protected_to_str: %s\n", chaine);

	delete_protected(pr);
 	pr = str_to_protected(chaine);


 	char* prPKey = key_to_str(pr->pKey);
 	char* prSgn = signature_to_str(pr->sgn);
 	printf("str_to_protected: %s %s %s\n", prPKey, pr->mess, prSgn);
 	delete_string(prPKey);
 	delete_string(prSgn);

 	delete_key(sKey);
 	delete_key(pKeyC);
	delete_key(sKeyC);

	delete_string(chaine);

	delete_string(mess);
	delete_string(pKeyStr);

	delete_protected(pr);

	delete_key(k);

	int nbCivils = NB_CITOYENS;
	int nbCandidats = NB_CANDIDATS;

	printf("\n\nLe test est "ANSI_COLOR_GREEN"terminé"ANSI_COLOR_RESET"\n");
	printf("\nLancement d'une génération de citoyen, vote et signature... (%d Citoyen(s), %d Candidat(s))\n", nbCivils, nbCandidats);

	sleep(5);

	generate_random_data(nbCivils, nbCandidats);

	printf("\n\nLa génération est "ANSI_COLOR_GREEN"terminée"ANSI_COLOR_RESET"\n");

	sleep(2);
	
	CellKey* cellKeys = read_public_keys("keys.txt");
	print_list_keys(cellKeys);

	CellKey* cellKeysCandidats = read_public_keys("candidates.txt");
	print_list_keys(cellKeysCandidats);


	CellProtected* cellProtected = read_protected("declarations.txt");
	print_list_protected(cellProtected);

	printf("\n\n"ANSI_COLOR_GREEN"Vérification"ANSI_COLOR_RESET" des signatures lus et enregistrés dans le fichier declarations.txt\n");

	sleep(2);

	verify_list_protected(&cellProtected);

	printf("\n\nLa vérification est "ANSI_COLOR_GREEN"terminée"ANSI_COLOR_RESET"\n");

	sleep(2);

	printf(ANSI_COLOR_GREEN"Détermination"ANSI_COLOR_RESET" du Vainqueur de l'élection...\n");

	sleep(1);
	
	Key* winnerKey = compute_winner(cellProtected, cellKeysCandidats, cellKeys, nbCandidats, nbCivils);

	sleep(2);


	//BlockChain

	//Write a block
	CellProtected* cellProtectedBlock = read_protected("declarations.txt");
	Key* blockKey = (Key*) malloc(sizeof(Key));
	init_key(blockKey, cellKeys->data->val, cellKeys->data->n);

	Block* bl = (Block *) malloc(sizeof(Block));
	bl->nonce = 1;
	bl->author = blockKey;
	bl->hash = (unsigned char*) strdup("JeSaisPas#9936");
	bl->previous_hash = (unsigned char*) strdup("#2#JeSaisPas#9936#2#");
	bl->votes = cellProtectedBlock;

	write_block_to_file("block.txt", bl);


	delete_key(bl->author);

	CellProtected* tempBl = bl->votes;
	CellProtected* temp;
	while (tempBl)
	{
		temp = tempBl->next;
		
		delete_protected(tempBl->data);

		tempBl = temp;
	}

	delete_block(bl);


	//Read a block
	Block* bl2 = read_block_from_file("block.txt");

	char* tempKeyStr = key_to_str(bl2->author);

	printf("%d\n", bl2->nonce);
	printf("%s\n", bl2->hash);
	printf("%s\n", bl2->previous_hash);
	printf("%s\n", tempKeyStr);
	print_list_protected(bl2->votes);

	char* t = block_to_str(bl2);

	printf("Let's try the str: %s\n", t);

	delete_string(t);

	compute_proof_of_work(bl2, 2);

	int success = verify_block(bl2, 2);
	printf("%d, %s\n", bl2->nonce, success == 1 ? "Block Valide" : "Block Invalide");

	delete_string(tempKeyStr);
	delete_block(bl2);
	


	delete_list_keys(cellKeys);
	delete_list_keys(cellKeysCandidats);
	delete_list_protected(cellProtected);

	delete_key(winnerKey);

	printf("\nFin du programme\n");
*/