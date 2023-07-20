const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();
const crypto = require('crypto');

server.use(middlewares);
server.use(jsonServer.bodyParser);

// Table pour stocker les codes de réinitialisation de mot de passe
const passwordResetCodes = {};

// Générer un code aléatoire pour la réinitialisation de mot de passe
function generateResetCode() {
    return crypto.randomBytes(3).toString('hex').toUpperCase();
}

// Envoi du code de réinitialisation de mot de passe par email (simulé)
function sendResetCodeByEmail(email, code) {
    console.log(`Un code de réinitialisation a été envoyé à l'adresse e-mail : ${email}`);
    console.log(`Code de réinitialisation : ${code}`);
}

// Étape 1: Demander un code de réinitialisation par email
server.post('/users/request-reset-code', (req, res) => {
    const { email } = req.body;
    const users = router.db.get('users');
    const user = users.find({ email }).value();

    if (user) {
        // Générer un nouveau code de réinitialisation
        const resetCode = generateResetCode();

        // Stocker le code de réinitialisation avec un jeton et une date d'expiration
        passwordResetCodes[email] = {
            token: crypto.randomBytes(20).toString('hex'),
            code: resetCode,
            expiresAt: Date.now() + 10 * 60 * 1000, // Code expirera dans 10 minutes (modifiable selon vos besoins)
        };

        // Envoi du code de réinitialisation par email (simulé)
        sendResetCodeByEmail(email, resetCode);

        // Répondre avec un statut 200 (OK) et un message de succès
        res.status(200).json({ message: 'Un code de réinitialisation a été envoyé à votre adresse e-mail.' });
    } else {
        res.status(404).json({ error: 'Utilisateur non trouvé.' });
    }
});

// Étape 2: Vérifier le code de réinitialisation et renvoyer un token
server.post('/users/verify-reset-code', (req, res) => {
    const { email, code } = req.body;
    const resetCode = passwordResetCodes[email];

    if (resetCode && resetCode.code === code && resetCode.expiresAt > Date.now()) {
        // Répondre avec un statut 200 (OK) et le token de réinitialisation
        res.status(200).json({ token: resetCode.token });
    } else {
        res.status(400).json({ error: 'Code de réinitialisation invalide ou expiré.' });
    }
});

// Étape 3: Réinitialiser le mot de passe de l'utilisateur avec le token
server.post('/users/reset-password', (req, res) => {
    const { token, newPassword } = req.body;
    const email = Object.keys(passwordResetCodes).find((key) => passwordResetCodes[key].token === token);

    if (email) {
        const users = router.db.get('users');
        const user = users.find({ email }).value();

        if (user) {
            // Mettre à jour le mot de passe de l'utilisateur
            user.password = newPassword;

            // Enregistre les modifications dans la base de données JSON
            router.db.write();

            // Supprimer le code de réinitialisation car il a été utilisé avec succès
            delete passwordResetCodes[email];

            // Répondre avec un statut 200 (OK) et un message de succès
            res.status(200).json({ message: 'Mot de passe réinitialisé avec succès.' });
        } else {
            res.status(404).json({ error: 'Utilisateur non trouvé.' });
        }
    } else {
        res.status(400).json({ error: 'Token de réinitialisation invalide.' });
    }
});

server.use(router);

const port = 3000;
server.listen(port, () => {
    console.log(`JSON Server is running on port ${port}`);
});
