ALGORITHME VTREE_X
ENTRÉES : 
    seed    : Tableau d'octets (graine initiale)
    D       : Tableau d'octets (identifiant de domaine/contexte)

FONCTIONS CRYPTOGRAPHIQUES REQUISES :
    H256(données) : Retourne le hachage SHA-256 (32 octets)
    H512(données) : Retourne le hachage SHA-512 (64 octets)
    extend(fragment) : Étend un fragment de 13 octets vers un bloc de 32 octets (padding)

DÉBUT

    // 1. Initialisation des clés et secrets maîtres
    K ← H512( seed || "VTREE-X-MasterKey" )
    S ← H512( K || "VTREE-X-InversionSecret" )
    
    // Initialisation du tableau contenant les 5 blocs de sortie
    O ← Tableau Vide de taille 5

    // 2. Boucle principale sur les 5 sous-branches (i = 0 à 4)
    POUR i DE 0 À 4 FAIRE:
        
        // Extraction du fragment F_i (13 octets de K)
        F_i ← K[13 * i POUR 13 * (i + 1)]
        
        // Initialisation de l'état initial du round 0
        X_r ← extend(F_i)
        
        // Cascade des 24 rounds cryptographiques
        POUR r DE 1 À 24 FAIRE:
            Taille_Etat ← Longueur(X_r)
            
            // Initialisation des vecteurs intermédiaires pour ce round
            M_r   ← Tableau d'octets de taille Taille_Etat
            R_R_r ← Tableau d'octets de taille Taille_Etat
            R_L_r ← Tableau d'octets de taille Taille_Etat
            XOR_r ← Tableau d'octets de taille Taille_Etat
            
            // Transformation parallèle sur chaque octet j de l'état
            POUR j DE 0 À (Taille_Etat - 1) FAIRE:
                M_r[j]   ← (X_r[j] * 0xD3) MOD 256
                R_R_r[j] ← X_r[j] >> 5
                R_L_r[j] ← X_r[j] << 7
                XOR_r[j] ← X_r[j] XOR S[j MOD 64]
            FIN POUR
            
            // Concaténation des structures et compression via H256
            Tampon_Round ← D || X_r || M_r || R_R_r || R_L_r || XOR_r
            X_r ← H256(Tampon_Round)
            
        FIN POUR (Fin des 24 rounds)
        
        // 3. Calcul de la signature et de la somme de contrôle
        C_i ← H256(X_r)   // X_r contient maintenant la valeur finale X_24
        
        // Extraction et opération XOR sur les indices clés, [15] et [31]
        chk_i ← C_i[0] XOR C_i[15] XOR C_i[31]
        
        // Construction du bloc unitaire O_i
        O[i] ← C_i || chk_i
        
    FIN POUR

    // Résultat final : Quintuplet (O_0, O_1, O_2, O_3, O_4)
    RETOURNER O

FIN
