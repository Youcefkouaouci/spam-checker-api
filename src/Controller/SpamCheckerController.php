<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Exception\BadRequestException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class SpamCheckerController extends AbstractController
{
    private const SPAM_DOMAINS = [
        'test.com',
        'hello.fr',
        'arnaque.net',
        'nour.ri',
        'bit.coin'
    ];

    #[Route('/api/check', name: 'api_spam_check', methods: ['POST'])]
    public function check(Request $request): Response
    {
        // J'extraie les données du corps de la requête
        // La méthode toArray utilise le flux php://input (le corps de la requête)
        // et le décode automatiquement depuis le format JSON, vers un tableau associatif

        // $request->toArray();

        $data = $request->toArray();
        // Je m'assure qu'au sein de ces données, se trouve bien
        // la clé "email", que j'attends.

        // json_decode($request->getContent(['email']));
        // $email = ['email'];
        if(!isset($data['email']) || empty($data['email'])){
            throw new BadRequestException('email is required');
            // return $this->json(['error' => 'Email est requis'], 400);
        }

        // Si cette clé est bien présente, alors j'en extraie la valeur
        // afin de pouvoir l'analyser : la valeur est bien l'email
        // En revanche, si je n'ai rien (pas de clé, ou bien valeur vide...),
        // Je renvoie un code 400 Bad Request

        $email = $data['email'];

        // Une fois l'email extrait, je valide son format
        // Je m'assure donc qu'il s'agit bien d'un email et non d'une chaîne
        // de caractères complètement aléatoire
        // Pour ce faire, en PHP pur, je peux utiliser la fonction de la SPL :
        // filter_var (https://www.php.net/manual/en/function.filter-var.php)
        // Si je me sens d'attaque, j'utilise à la place un package Composer :
        // egulias/email-validator (https://packagist.org/packages/egulias/email-validator)

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return $this->json(['error' => 'Email INVALIDE BRO'], 400);
        }

        // Une fois l'email validé, j'en extraie le domaine à l'aide d'un petit algorithme.
        $domaine = explode('@', $email)[1];

        if(in_array($domaine, self::SPAM_DOMAINS )){
            return $this->json(['result' => 'spam']);
        }
        // Enfin, je vérifie que le domaine de cet email ne se trouve pas dans mon tableau (ou ma source de données) de domaines considérés comme des spams
        // S'il s'y trouve : spam
        // S'il en est absent : non spam (ok)

        // Je renvoie ma réponse au client, suivant la situation :
        // 'result' => 'spam' si c'est un spam
        // 'result' => 'ok'   si ça n'est pas un spam
        return $this->json(['result' => 'spam']);
    }
}