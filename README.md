# توزيع المهام — app de partage des tâches

Application web (Node.js + PostgreSQL) pour répartir les tâches d'une équipe. Interface en arabe.

- Chaque salarié pioche **une tâche à la fois**, règle son avancement et remplit « قسمي » (sa partie), visible par toute l'équipe.
- **Découper une tâche** (« 🧩 المهام الفرعية ») : la personne qui a la tâche, ou l'admin, ajoute des sous-tâches. Chacune est soit une **étape** gardée pour soi (à cocher), soit une **sous-tâche pour l'équipe**, envoyée dans la pioche. L'avancement se calcule alors tout seul. Chaque sous-tâche a son propre texte (on l'ouvre en touchant son titre) : le texte de l'étape, ou les consignes d'une sous-tâche partagée avec, en dessous, ce qu'a écrit le collègue qui l'a prise. Une tâche partagée passe dans « مهام أنسّقها » : son responsable peut piocher une autre tâche en attendant, et il ne peut la terminer que quand toutes ses sous-tâches sont finies.
- Les salariés **proposent** des tâches, et l'admin les valide. Les tâches ajoutées par l'admin vont directement dans la pioche.
- Barre d'avancement globale, tableau d'honneur, synchronisation en temps réel.
- L'admin gère l'équipe : rôle admin, nouveau mot de passe, suppression de compte.

## Déployer sur Railway

1. Sur [railway.com](https://railway.com), clique sur **New Project → Deploy from GitHub repo** et choisis ce dépôt (`MohamedALMAHMOUD/todo`).
2. Dans le projet, clique sur **+ New → Database → Add PostgreSQL**.
3. Ouvre le service de l'app, onglet **Variables**, et ajoute :

   | Variable | Valeur |
   |---|---|
   | `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` (référence vers la base) |
   | `ADMIN_USERNAME` | ton identifiant, par exemple `mohamed` |
   | `ADMIN_PASSWORD` | ton mot de passe admin |
   | `ADMIN_NAME` | le nom affiché, par exemple `محمد` |
   | `JOIN_CODE` | le code que tu donneras aux salariés |
   | `SESSION_SECRET` | une longue chaîne aléatoire |

4. Onglet **Settings → Networking → Generate Domain** : tu obtiens l'adresse publique de l'app.
5. Ouvre l'adresse et connecte-toi avec ton compte admin. Dans l'onglet **الفريق**, la section « إدارة الفريق » affiche le code d’inscription à envoyer aux salariés, avec un bouton pour le copier.

Les salariés ouvrent l'adresse, choisissent « أنشئ حساباً » et entrent le code d’inscription. Pour fermer les inscriptions, il suffit de vider `JOIN_CODE`.

Chaque `git push` sur la branche `main` redéploie automatiquement l'app sur Railway.

## Lancer en local

```bash
npm install
DATABASE_URL=postgresql://user:pass@localhost:5432/taches ADMIN_USERNAME=mohamed ADMIN_PASSWORD=secret JOIN_CODE=code npm start
```

Base distante en SSL (URL publique Railway) : ajoute `PGSSL=true`.
