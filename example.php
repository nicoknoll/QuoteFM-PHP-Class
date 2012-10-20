<?php
require_once 'quotefm.php';

$qfm = new QUOTEfm('<consumer key>', '<consumer secret>');
$redirectUrl = '';

if(!isset($_GET['code']) && !$qfm->oAuthLoadTokenFromCookie() && !$qfm->oAuthLoadTokenFromSession()) {
	$qfm->oAuthAuthorize($redirectUrl);
} elseif($qfm->oAuthLoadTokenFromCookie() || $qfm->oAuthLoadTokenFromSession()) {
	$token = (($qfm->oAuthLoadTokenFromCookie() != '') ? $qfm->oAuthLoadTokenFromCookie() : $qfm->oAuthLoadTokenFromSession());
	$qfm->setAccessToken($token);
} else {
	$qfm->oAuthRequestToken($_GET['code'], $redirectUrl);
	$qfm->oAuthSaveTokenAsSession();
}

var_dump($qfm->recommendationGet('<id>'));

?>