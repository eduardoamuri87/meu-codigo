<?php
/**
 * Template name: Lista usuários
 * Página com listagem dos cursos
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */
if ( ! is_user_logged_in() ) wp_redirect( get_permalink( get_option('woocommerce_myaccount_page_id') ) );
 
get_header();
?>

<?php
function user_exists_by_email( $email ) {
    return email_exists( $email );
}

$emails = [
'eduardo@amuri.com.br',
'anamr86@gmail.com',
'brunalcallegretti@gmail.com',
'marilia.carneiro@alumni.usp.br',
'zezebenetti@gmail.com',
'zezinhamartel@gmail.com',
'bianchibritoj@gmail.com',
'gabrielamrcunha.carreira@gmail.com',
'ezilcp@gmail.com',
'saramoraes7maio@gmail.com',
'julierrmelo@gmail.com',
'kahenista@gmail.com',
'adrianolopes.arq@gmail.com',
'martinslobojardim@gmail.com',
'belawogeley@gmail.com',
'thaisbcampos@icloud.com',
'camilaluzadv@hotmail.com',
'mateus.dumas@gmail.com',
'trabalhofacul31@gmail.com',
'taticastroamato@gmail.com',
'renatasilvapersonal@gmail.com',
'dariane.s.aguiar@gmail.com',
'emile8048@yahoo.com.br',
'passos_carla@yahoo.com.br',
'pedro@saladealma.org.br',
'ane_rochha@hotmail.com',
'dripadilhapascotto@gmail.com',
'anax.antonio@gmail.com',
'thaisa.pereira92@gmail.com',
'cosanlara@gmail.com',
'maarina.aguiar@gmail.com',
'amanda@controllcontabilidade.com.br',
'thalitatomazi89@gmail.com',
'cristianoramalho@gmail.com',
'klaurenti@gmail.com',
'gabriela_fp@hotmail.com',
'murilopagani@hotmail.com',
'vanessa.lima@gmail.com',
'muniz_leonardo@hotmail.com',
'felipe.eltermann@gmail.com',
'corradini.lela@gmail.com',
'mirleywohlers@gmail.com',
'alicechaves@gmail.com',
'joaovitorbgr@gmail.com',
'danitrois@gmail.com',
'sammymbr@yahoo.com.br',
'janine.rosset@yahoo.com.br',
'pamella.marchao@gmail.com',
'ftsyamanishi@gmail.com',
'mariana.fagundes.rivera@gmail.com',
'anacurvo@gmail.com',
'ccbaporto@gmail.com',
'denise.silvestrin@gmail.com',
'simone_ch77@hotmail.com',
'gmsarti@gmail.com',
'carla.suarezjn@gmail.com',
'gabrielabosi@gmail.com',
'lumina.cap@gmail.com',
'jakebarbosa.jb@gmail.com',
'aiana_camila@hotmail.com',
'leoduarte05@gmail.com',
'ester.freire13@gmail.com',
'samara.lobe@gmail.com',
'tatianarprado@gmail.com',
'mabel_erica@yahoo.com.br',
'caramuru87@hotmail.com',
'thaisroloff@hotmail.com',
'mab2512@hotmail.com',
'hannah23@gmail.com',
'l.strozenberg@gmail.com',
'dsviech@yahoo.com.br',
'queldsa@gmail.com',
'annapopsilv@gmail.com',
'gumiaciro@gmail.com',
'mirelalarssen@gmail.com',
'yaratropea@gmail.com',
'rodrigonanuvem@gmail.com',
'lucianamaran@yahoo.com.br',
'danielbaffini@gmail.com',
'igordesouza182@gmail.com',
'fernandav.br@gmail.com',
'vinicius.airuman@gmail.com',
'larissa.silvar@hotmail.com',
'assimelajavai@gmail.com',
'marianam85@gmail.com',
'brognolijose@gmail.com',
'fatima.portela@outlook.com',
'cariocaelen@gmail.com',
'eduflavianosc@gmail.com',
'acmouraa@gmail.com',
'anacarolina.lcarvalho@gmail.com',
'miyukisonia@gmail.com',
'msumienski@gmail.com',
'valentimmvoc@gmail.com',
'telmag@uol.com.br',
'cybele.leite@gmail.com',
'lilipusas@gmail.com',
'rodrigofmelo.sa@gmail.com',
'camilasimielli@hotmail.com',
'tatigmc@gmail.com',
'jugranjeia@proton.me',
'murielkong@gmail.com',
'rodfaleiros@gmail.com',
'gabrieljrmirand@gmail.com',
'elisapsc@gmail.com',
'natalia@ateliefinanceiro.com.br',
'robertosantos@pobox.com',
'ivsonmenezes@gmail.com',
'rubens.sperandio@hotmail.com',
'contato@ayshacorrea.com.br',
'fabihirata@yahoo.com.br',
'ana.belosevich@gmail.com',
'danielluisdasilva@gmail.com',
'renatagnetto@gmail.com',
'mirianbritodias@gmail.com',
'ninavilela@gmail.com',
'nanecardozo@hotmail.com',
'cynthiasilvamachado@yahoo.com.br',
'jtiagorn@gmail.com',
'mayara_canever@hotmail.com',
'camila@camilacavallari.com',
'suhahn@hotmail.com',
'patrickpreato@gmail.com',
'lubotter@gmail.com',
'ola@taissouza.com.br',
'imirafonseca@gmail.com',
'eduardoep09@gmail.com',
'drica_elizabeth@hotmail.com',
'psicfernandobasso@gmail.com',
'lorenagomes@uol.com.br',
'carolinanikaedo@gmail.com',
'crismiranda18@uol.com.br',
'popnina123@gmail.com',
'more.amanda@gmail.com',
'bpassos@gmail.com',
'lcschagas@gmail.com',
'silviaolive@gmail.com',
'gabivolpe@gmail.com',
'contatofelopes@gmail.com',
'jonathancbatista@gmail.com',
'isis.bussons@gmail.com',
'campelo.ju@gmail.com',
'tlgenaro@gmail.com'
];
echo 'count: ' . count( $emails ) . '<br>';
// $user_email =  'a@a.com';
// $user_exists = user_exists_by_email( $user_email );

$count = 0;
foreach ( $emails as $email ) {
    $count++;
    $user_exists = user_exists_by_email( $email );
    if ( $user_exists ) {
        $user_id = (int) $user_exists;
        echo '--------------------<br>';
        echo $count . '. Usuário ' . $email . ' existe / id: ' . $user_id . '<br>';
        $memberships = wc_memberships_get_user_active_memberships( $user_id );
        if ( ! empty( $memberships ) ) {
            echo ' - Já possui associação ativa. Criando associação ao FPA...<br>';
  //          $args_fpa = array( 'plan_id' => 206, 'user_id' => $user_id );
//            wc_memberships_create_user_membership( $args_fpa );
        }
    }
}
?>

<?php get_footer(); ?>
