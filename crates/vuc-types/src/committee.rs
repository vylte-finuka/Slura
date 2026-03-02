// crates/vuc_types/src/committee/committee.rs
// (ou l'endroit où tu veux le placer)

use std::collections::HashMap;

/// Type alias clair et utilisé partout dans le projet pour l'identifiant d'époque
pub type EpochId = u64;

/// Représente un comité pour une époque donnée.
/// Chaque membre a un poids (stake, pouvoir de vote, etc.).
#[derive(Debug, Clone)]
pub struct Committee {
    /// Identifiant de l'époque (numéro unique et croissant)
    pub epoch_id: EpochId,
    
    /// Mapping : adresse ou identifiant du membre → son poids dans le comité
    members: HashMap<String, u64>,
}

impl Committee {
    /// Crée un nouveau comité vide pour l'époque donnée
    pub fn new(epoch_id: EpochId) -> Self {
        Self {
            epoch_id,
            members: HashMap::new(),
        }
    }

    /// Ajoute ou met à jour un membre avec son poids
    pub fn add_member(&mut self, member_id: String, weight: u64) {
        self.members.insert(member_id, weight);
    }

    /// Récupère le poids d'un membre (Option<&u64>)
    pub fn get_member_weight(&self, member_id: &str) -> Option<&u64> {
        self.members.get(member_id)
    }

    /// Retourne le poids total du comité (somme des poids de tous les membres)
    pub fn total_weight(&self) -> u64 {
        self.members.values().copied().sum()
    }

    /// Vérifie si le comité est vide
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Nombre de membres dans le comité
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Retourne une référence immutable à la map interne (si besoin d'itérer)
    pub fn members(&self) -> &HashMap<String, u64> {
        &self.members
    }

    /// Crée une copie du comité avec un epoch_id incrémenté
    pub fn next_epoch(&self) -> Self {
        Self {
            epoch_id: self.epoch_id.saturating_add(1),
            members: self.members.clone(),
        }
    }
}

// Optionnel : implémentation de Default si tu veux un comité "vide" par défaut
impl Default for Committee {
    fn default() -> Self {
        Self::new(0)
    }
}