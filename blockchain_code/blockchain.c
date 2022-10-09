#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <dirent.h>
#include <openssl/sha.h>

#include "../rsa/rsaH.h"
#include "../primal/primalH.h"
#include "../key/keyH.h"
#include "../signature/signatureH.h"
#include "../protected/protectedH.h"
#include "../cellkey/cellkeyH.h"
#include "../cellprotected/cellprotectedH.h"
#include "../hashtable/hashtableH.h"
#include "../blockchain_code/blockchainH.h"


//Création d'un block à partir des différents champs requis
Block *creerBlock(Key *author, CellProtected *votes, unsigned char *hash, unsigned char *previous_hash, int nonce)  {
    Block *new = (Block *)malloc(sizeof(Block));
    if (!new)
    {
        fprintf(stderr, "[creerBlock function] new => NULL\n");
        return NULL;
    }

    //Copie des hashes
    unsigned char *h = (unsigned char*) malloc((strlen((char *) hash) + 1) * sizeof(unsigned char));
    unsigned char *ph = (unsigned char*) malloc((strlen((char *) previous_hash) + 1) * sizeof(unsigned char));
    int i;
    for (i=0; i < strlen((char *)hash); i++)	{
        h[i] = hash[i];
    }
    h[i] = (unsigned char)'\0';
    for (i=0; i < strlen((char *)previous_hash); i++)     {
        ph[i] = previous_hash[i];
    }
    ph[i] = (unsigned char)'\0';

    new->author = author;
    new->votes = votes;
    new->hash = h;
    new->previous_hash = ph;
    new->nonce = nonce;
    return new;
}

//Libérer la mémoire associé a un block
void delete_block(Block* B)
{
    if (!B)	{
        fprintf(stderr,"[delete_block function] block => null\n");
        return;
    }

    free(B->author);
    free(B->hash);
    free(B->previous_hash);
    delete_list_protected(B->votes);
    free(B);

    return;
}

//Affichage d'un string haché
void print_sha256_string(const unsigned char* hash)
{
    if (!hash)
    {
        fprintf(stderr,"[print_sha256_string function] hash => null\n");
        return;
    }

	for (int k = 0; k < SHA256_DIGEST_LENGTH; k++)
		printf("%x", hash[k]);
	putchar('\n');
}

//Écriture d'un block dans un fichier
void write_block(char* filename, Block* block)
{
	FILE *ostream = fopen(filename,"w");
    if (ostream == NULL)    {
        fprintf(stderr,"[write_block function] Erreur a l'ouverture du fichier %s en ecriture\n", filename);
        return;
    }
    char *author = key_to_str(block->author);
    
    //on écrit dans le fichier ostream les données du block
    fprintf(ostream,"%s %s %s %d\n",author, block->hash, block->previous_hash, block->nonce);
    CellProtected *voteList = block->votes;
    while (voteList) {
        char *str = protected_to_str(voteList->data);
        fprintf(ostream, "%s\n",str);
        voteList = voteList->next;
        free(str);
    }
    free(author);
    fclose(ostream);

    return;
}

//Lecture d'un block depuis un fichier
Block* lireBlock(char* filename)
{
	FILE *istream = fopen(filename,"r");
    if (istream == NULL)
    {
        fprintf(stderr, "[lireBlock function] Erreur a l'ouverture du fichier %s en lecture\n", filename);
        return NULL;
    }
    char buffer[2048];
    char authorStr[32];
    unsigned char hash[256];
    unsigned char previous_hash[256];
    int nonce;

    //Lecture de la premiere ligne
    if (fgets(buffer,4096,istream) == NULL)
    {
        fprintf(stderr,"[lireBlock function] Erreur a la lecture de la premiere ligne du ficher %s\n", filename);
        fclose(istream);
        return NULL;
    } else {
        if (sscanf(buffer,"%s %s %s %d\n",authorStr,hash,previous_hash,&nonce) != 4)
        {
            fprintf(stderr, "[lireBlock function] Erreur de formatage de la premiere ligne du fichier\n");
            fclose(istream);
            return NULL;
        }
    }

    //Lecture des votes (on remet dans l'ordre des votes)
    CellProtected *votesTmp = NULL;
    while (fgets(buffer,4096,istream) != NULL)   {
        Protected *pr = str_to_protected(buffer);   //ne pas désallouer pr !
        add_cell_protected(&votesTmp,pr);
    }

    fclose(istream);

    CellProtected *votesTmpBis = votesTmp;
    CellProtected *votes = NULL;
    while (votesTmp)    {
        add_cell_protected(&votes,votesTmp->data);
        votesTmp = votesTmp->next;
    }

    //On libere votesTmp, mais pas son contenu
    CellProtected *tmp;
    while (votesTmpBis) {
        tmp = votesTmpBis;
        votesTmpBis = votesTmpBis->next;
        free(tmp);
    }

    return creerBlock(str_to_key(authorStr),votes,hash,previous_hash,nonce);
}

//Conversion d'une structure Block en string pour un format lisible
char* block_to_str(Block* block)
{
    if (!block)
    {
        fprintf(stderr, "[block_to_str function] block => NULL");
        return NULL;
    }

	//on prend un buffer assez grand pour tout stocker
    char buffer[4096];
    buffer[0] = '\0';
    char previous_hash[256];
    char nonce[32];

    //on obtient les informations et les concatene au buffer
    char *author = key_to_str(block->author);
    strcat(buffer,author);

    sprintf(previous_hash, " %s ", block->previous_hash);
    //fprintf(stderr,"\n\nblock_to_string : \nbuffer = %s\nprevious_hash = %s\n\n",buffer,previous_hash);
    strcat(buffer,previous_hash);

    CellProtected *votes = block->votes;
    while (votes)   {
        char *prStr = protected_to_str(votes->data);
        strcat(buffer,prStr);
        strcat(buffer, " ");
        free(prStr);
        votes = votes->next;
    }

    sprintf(nonce, "%d", block->nonce);
    strcat(buffer,nonce);

    free(author);

    //on alloue avec strdup avant de renvoyer
    return strdup(buffer);
}

//Haché un block
unsigned char* hash_function_block(const char* str)
{
    if (!str)
    {
        fprintf(stderr, "[hash_function_block function] str => NULL");
        return NULL;
    }

    char *res = (char*) malloc(2*SHA256_DIGEST_LENGTH+1);
    char buffer[2*SHA256_DIGEST_LENGTH+1];
    unsigned char* d = SHA256((const unsigned char*) str, strlen(str), 0);
    res[0]='\0';
    buffer[0]='\0';
    //on transforme la chaine en écriture héxadécimal
    for (int i=0; i<SHA256_DIGEST_LENGTH; i++){
        strcpy(buffer, res);
        sprintf(res,"%s%02x",buffer,d[i]);
        buffer[0] = '\0';   //on veut s'assurer que le contenu du buffer soit efface
    }
    return (unsigned char*) res;
}

//Compter le nombre de zéros au debut d'un hash
int count_zeros(unsigned char* str){
    if (!str){
        fprintf(stderr,"[count_zeros function] str => NULL");
        return -1;
    }

    int nbZeros = 0;
    int taille_str = strlen((const char*) str);

    //on compte le nombre de zéro d'affilé en tête de str
    while ((nbZeros<taille_str) && (str[nbZeros]=='0'))
        nbZeros++;

    return nbZeros;
}

//Bruteforce le Hash
void compute_proof_of_work(Block *B, int d)
{
	if (!B)
	{
		fprintf(stderr, "[compute_proof_of_work Function] B => NULL\n");
		return;
	}

	B->nonce = 0;
    char* str = block_to_str(B);
    unsigned char* hash = hash_function_block((const char*) str);

    //tant qu'il n'y a pas "d" zéros en tête de hash, on incrémente nonce et on recalcule hash
    while (count_zeros(hash) < d)
    {
        free(str);
        free(hash);
        B->nonce ++;
        str = block_to_str(B);
        hash = hash_function_block((const char*) str);
    }
    free(str);

    free(B->hash);  //il faut liberer le hash qu'on a utilise pour initialiser le bloc avant de le remplacer
    B->hash = hash;
}

//Vérifie si le hash du block B
int verify_block(Block* B, int d)
{
	if (!B)
	{
		fprintf(stderr, "[verify_block Function] B => NULL\n");
		return 0;
	}

	// Verifie que le nombre de zeros au debut du block hash est superieur ou  egal a d
    char *str = block_to_str(B);
    unsigned char *hashed = hash_function_block(str);
    int res = count_zeros(hashed) >= d;
    free(hashed);
    free(str);
    return res;
}


//Création d'un noeud pour l'insérer dans l'arbre
CellTree* create_node(Block* b)
{
	if (!b)
	{
        fprintf(stderr, "[create_node Function] B => NULL\n");
		return NULL;
	}

	CellTree* ct = (CellTree*) malloc(sizeof(CellTree));
	if (!ct)
	{
        fprintf(stderr, "[create_node Function] malloc ct => NULL\n");
		return NULL;
	}

	ct->height = 0;
	ct->father = NULL;
	ct->firstChild = NULL;
	ct->nextBro = NULL;
	ct->block = b;

	return ct;
}

//Modifie la hauteur de l'arbre
int update_height(CellTree* father, CellTree* child)
{
	 
    if ((father == NULL)||(child == NULL))  {
        fprintf(stderr,"[update_height function] father or child => null\n");
    }
    if (child->father != father)	{
        fprintf(stderr,"[update_height function] You are NOT the father\n");
    }
    if (father->height < child->height+1){
        father->height = child->height+1;
        return 1;
    }else {
        //on ne modifie pas le père
        return 0;
    }
}


//Ajout d'un fils
void add_child(CellTree* father, CellTree* child)
{
	if (child == NULL || father == NULL)  {
        fprintf(stderr,"[add_child function] child or father => null\n");
        return;
    }
    //On actualise le previous hash de child
    if ( strcmp((char *)child->block->previous_hash, (char *)father->block->hash) != 0 ) {
        fprintf(stderr,"[add_child function] You are not HIS child!\n");
        return;
    }

    //on actualise le pere de child
    child->father = father;
    
    //on ajoute le fils
    CellTree *curr = father->firstChild;
    if (curr == NULL)   {
        father->firstChild = child;
    }else{
        //on cherche le dernier des frères du fils du père
        while (curr->nextBro)   {
            curr = curr->nextBro;
        }
        curr->nextBro = child;
    }

    //on met à jour la hauteur des pères tant qu'il y a des modifications
    CellTree *fathers = father;
    CellTree *children = child;
    int modification = 1;
    while ((fathers)&&(modification==1))    {
        modification = update_height(fathers,children);
        children = fathers;
        fathers = fathers->father;
    }  
}

//Affichage de l'arbre
void print_tree(CellTree* tree)
{
	if (!tree)
        return;

	//on affiche le noeud courrant
    printf("Block de hauteur : %d, et d'identifiant : %s\n", tree->height, tree->block->hash);
    
    //on appelle la fonction pour ses frères puis ses fils
    if (tree->nextBro){
        print_tree(tree->nextBro);
    }
    if (tree->firstChild){
        print_tree(tree->firstChild);
    }

	return;
}

//Suppresion d'un noeud
void delete_node(CellTree* node)
{
	if (!node)
	{
		printf("[delete_node Function] node => NULL\n");
		return;
	}

    delete_block(node->block);
    free(node);

	return;
}

//Suppression de tous l'arbre
void delete_tree(CellTree* tree)
{
	if (tree)
    {
        CellTree *brothers = tree->nextBro;
        CellTree *children =  tree->firstChild;

        //on supprime le noeud courant 
        delete_node(tree);

        //on supprime ses frères puis ses fils
        delete_tree(brothers);
        delete_tree(children);
    }

	return;
}

//Retourne le plus grand fils
CellTree* highest_child(CellTree* cell)
{
    //retourne l'adresse du fils dont la hauteur est la plus grande
    if (!cell)  
    {
        fprintf(stderr,"[highest_child function] tree => empty\n");
        return NULL;
    }

    //retourne l'adresse du fils dont la hauteur est la plus grande
    if (!cell)
    {
        fprintf(stderr,"[highest_child function] cell => null\n");
        return NULL;
    }

    CellTree* child = cell->firstChild;
    CellTree* highest_child = cell->firstChild;
    while(child)
    {
        if (child->height > highest_child->height)
            highest_child = child;

        child = child->nextBro;
    }
    return highest_child;
} 

//Retourne le dernier noeud de la plus grande branche
CellTree* last_node(CellTree *tree)
{
    //Retourne la feuille de la plus longue branche
    if (tree == NULL)   {
        return NULL;
    }
    //renvoie une feuille
    if (tree->firstChild == NULL)   {
        return tree;
    //parcourt le plus grand fils    
    } else {
        return last_node(highest_child(tree));
    }
}

//Retourne la liste des votes de la plus grande branche
CellProtected* votesBrancheMax(CellTree *tree)   {
    //on fusionne les listes de votes de la plus longue branche
    if (tree == NULL)   {
        fprintf(stderr, "[votesBrancheMax function] tree => NULL\n");
        return NULL;
    }

    CellTree *node = last_node(tree);
    CellProtected *res = NULL;
    while (node != NULL)
    {
        res = fusionner_list_protected(res, copie_list_protected(node->block->votes));
        node = node->father;
    }
    return res;
}

//Soumission d'un vote
void submit_vote(Protected *p)
{
    FILE *ostream = fopen("Pending_votes.txt","a"); //cree le fichier s'il n'existe pas
    if (!ostream) 
    {
        fprintf(stderr,"[submit_vote function] output stream => NULL\n");
        return;
    }

    char *vote = protected_to_str(p);
    fprintf(ostream,"%s\n",vote);
    free(vote);
    fclose(ostream);
}

//Création d'un block pour l'ajouter à l'arbre
void create_block(CellTree **tree, Key *author, int d)
{ 
    //On a modifie la signature pour pouvoir acceder a la tete de l'arbre
    //Creation d'un bloc valide a partir de Pending_votes.txt
    CellProtected *votes = read_protected("Pending_votes.txt"); //ce qu'on met dans le bloc
    //print_list_protected(votes);
    
    CellTree *leaf = last_node(*tree);
    unsigned char previous_hash[2*SHA256_DIGEST_LENGTH+1];
    int i;
    //On obtient le previous_hash
    if (leaf == NULL)   {   //Genesis Block
        previous_hash[0] = '0';
        previous_hash[1] = '\0';
    } else {
        for (i=0; i<(2*SHA256_DIGEST_LENGTH+1); i++)    {
            previous_hash[i] = leaf->block->hash[i];  
        }
        previous_hash[i] = '\0';

    }
    Block *b = creerBlock(author,votes,(unsigned char *)"0",previous_hash,0); // ne pas desallouer le bloc !
    compute_proof_of_work(b,d);
    CellTree *new = create_node(b);
    //On gere le Genesis Block de la chaine
    if (leaf == NULL)   {
        *tree = new;
    } else {    
        add_child(leaf,new);    //on sait que l'arbre est non vide
    }

    assert(remove("Pending_votes.txt") == 0);
    write_block("Pending_block.txt", b);
    //on conserve le block dans l'arbre
}

//Ajout d'un block à la blockchain
void add_block(int d, char *name)
{
    Block *b = lireBlock("Pending_block.txt");
    if (!b) 
    {
        fprintf(stderr,"[add_block function] b => NULL\n");
        return;
    }

    int verified = verify_block(b, d);
    if (verified)
    {
        char path[256] = "\0";
        strcat(path,"./Blockchain/");
        strcat(path,name);
        write_block(path, b);
    }
    assert(remove("Pending_block.txt") == 0);
    free(b->author);
    free(b->hash);
    free(b->previous_hash);
    delete_list_protected(b->votes);
    free(b);
}

//Création de l'abre CellTree à partir du répertoire ./Blockchain/
CellTree *read_tree()   {
    DIR *rep = opendir("./Blockchain/");
    if (!rep)
    {
        fprintf(stderr, "[read_tree function] directory => NULL\n");
        return NULL;
    }

    //on compte d'abord le nombre de fichiers
    int nbFichiers = 0;
    struct dirent *dir;
    while ((dir = readdir(rep)))
        if (strcmp(dir->d_name,".") != 0 && strcmp(dir->d_name,"..") != 0)
            nbFichiers++;
    closedir(rep);

    //creation du tableau
    CellTree *tab[nbFichiers];
    for (int i = 0; i < nbFichiers; i++)
        tab[i] = NULL;

    //creation d'un noeud par fichier
    rep = opendir("./Blockchain/");
    Block *b = NULL;
    char path[1024];
    int i = 0;
    while ((dir = readdir(rep)))    {
        if (strcmp(dir->d_name,".") != 0 && strcmp(dir->d_name,"..") != 0)   {
            path[0] = '\0';
            strcat(path,"./Blockchain/");
            strcat(path,dir->d_name);

            b = lireBlock(path);
            
            tab[i] = create_node(b);
            i++;
        }
    }
    closedir(rep);

    //on ajoute a chaque noeud ses fils
    int pere,fils;
    for (pere=0; pere<nbFichiers; pere++)   {
        for (fils=0; fils<nbFichiers; fils++)   {
            if (strcmp((char *)tab[pere]->block->hash,(char *)tab[fils]->block->previous_hash) == 0)    {
                add_child(tab[pere],tab[fils]);
            }
        }
    }

    //on cherche la racine de l'arbre
    CellTree *racine = NULL;
    int nbRacines=0;    //verification de l'unicite de la racine
    for (i = 0; i < nbFichiers; i++)    {
        if (tab[i]->father == NULL) {
            racine = tab[i];
            nbRacines++;
        }
    }

    if (nbRacines == 1) {
        return racine;
    } else {
        fprintf(stderr,"[read_tree function] racine non unique ou non existante\n");
        for (i = 0; i < nbFichiers; i++)    {
            if (tab[i] == NULL)
                fprintf(stderr, "tab[%d] NULL\n", i);
            else
                delete_node(tab[i]);
        }
        return NULL;
    }
}

//Calcul du gagnant de l'élection
Key *compute_winner_BT(CellTree *tree, CellKey *candidates, CellKey *voters, int sizeC, int sizeV)  {
    //verification de sizeC >= len(candidates) && sizeV >= len(voters)
    assert((sizeC >= listKeyLength(candidates)) && (sizeV >= listKeyLength(voters)));

    //extraction de la liste des declarations de vote valides
    CellProtected* votes = votesBrancheMax(tree);
    verify_list_protected(&votes);

    //Calcul du gagnant
    Key *gagnant = compute_winner(votes, candidates, voters, sizeC, sizeV);
    
    //on libere les cellules mais pas les protected
    CellProtected *tmp;
    while (votes)
    {
        tmp = votes;
        votes = votes->next;
        free(tmp);
    }

    return gagnant;
}