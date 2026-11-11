<?php
/**
 * The 404 NOT FOUND page
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

get_header();

?>

<article class="text-center py-[20vh] px-[15px] lg:px-[30px] min-h-[50vh] flex justify-center items-center flex-col">
    <img class="my-[40px] max-w-[200px]" src="<?php echo public_url(); ?>images/logo-amuri.png" alt="" width="589" height="389">
    <h1 class="typog-title"><?php esc_attr_e('Página não encontrada','amrwp'); ?></h1>
    <p class="typog-body-med my-[40px]"><?php esc_attr_e('O conteúdo que procura não está aqui ou foi removido.','amrwp'); ?></p>
</article>

<?php get_footer(); ?>
