<?php
/**
 * Template name: Minha conta
 * Página com formulário para acessar o sistema
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

get_header();

if ( is_user_logged_in() ) {
    wp_redirect( get_permalink( 211 ) );
}

if ( ! is_user_logged_in() ) {
?>

<div class="lg:w-[830px] mx-auto lg:flex lg:m-[30px] bg-white lg:rounded-r-[20px] lg:border-bottom-right-[20px] form-login-wrapper">
    <?php
    if ( function_exists("get_field") && get_field("ilustracoes") ) {
        $ilustracoes = get_field("ilustracoes");
        $k = array_rand($ilustracoes);
        $v = $ilustracoes[$k];
    ?>
    <div class="lg:bg-orange-light mxlg:hide lg:flex lg:items-center"><?php amrwp_img_tag_generate( $v, 'full', 'translate-x-[5%]', false ); ?></div>
    <?php } ?>
    <div class="lg:min-w-[410px] lg:py-[50px] lg:flex lg:py-[10px] lg:px-[35px] lg:flex lg:flex-col lg:justify-center mxlg:px-[30px] mxlg:py-[9vh]">
        <h1 class="typog-title"><?php esc_attr_e('Entrar na conta','amrwp'); ?></h1>
        <div class="mt-[30px] lg:mt-[50px] form-login">
            <?php
            while ( have_posts() ): the_post();
                the_content();
            endwhile;
            ?>
        </div>
    </div>
    
</div>
<!-- /.page-login-wrapper -->

<?php
} else { // if ( ! is_user_logged_in() ) {
    echo '<a href="' . wp_logout_url() . '">deslogar</a>';
    while ( have_posts() ): the_post();
        the_content();
    endwhile;
    
} // if ( ! is_user_logged_in() ) {
?>

<?php get_footer(); ?>