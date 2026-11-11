<?php
/**
 * The template for displaying the header
 *
 * Displays all of the head element and everything up until the "site-content" div.
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

 global $post;
 $post_id = $post->ID;
 $header_user_can_access = true;
 if ( 'lesson' == get_post_type( $post_id ) ) {
     $lesson_id = $post_id;
     if ( get_post_meta( $lesson_id, '_lesson_course', true ) ) {
         $post_id = get_post_meta( $lesson_id, '_lesson_course', true );
         if ( function_exists('wc_memberships_user_can') && ! wc_memberships_user_can( get_current_user_id(), 'view', array( 'course' => $post_id ) ) ) {
             $header_user_can_access = false;
         }
         
     }
 }

?><!DOCTYPE html>
<html <?php language_attributes(); ?> data-is-mobile="<?php echo wp_is_mobile(); ?>">
<head>

    <?php
        // Google Analytics - código de monitoramento
        if ( ! is_user_logged_in() && 'production' == AMBIENT_VAR_DEF ) {
    ?>

    <?php
        } // if ( ! is_user_logged_in() && 'production' == AMBIENT_VAR_DEF ) {
    ?>

    <meta charset="<?php bloginfo( 'charset' ); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="profile" href="http://gmpg.org/xfn/11">
    <?php if ( is_singular() && pings_open( get_queried_object() ) ) : ?>
    <link rel="pingback" href="<?php bloginfo( 'pingback_url' ); ?>">
    <?php endif; ?>
    <meta content="telephone=no" name="format-detection">

    <?php wp_head(); ?>

</head>

<body <?php body_class('font-sans'); ?> data-is-mobile="<?php echo wp_is_mobile(); ?>">
    <?php do_action('after_body'); ?>

    <div id="top"></div>

    <div id="page">

        <?php
        global $post;
        $pageID = $post->ID;
        $course_id = amrpw_get_program_course_id();
        
        if ( ! empty($course_id) && function_exists('get_field') ) {
            if ( get_field('pgm_lgtp_img_min',$course_id) ) {
                $pgm_lgtp_img_min = get_field('pgm_lgtp_img_min',$course_id);
            }
            if ( get_field('pgm_lgtp_img',$course_id) ) {
                $pgm_lgtp_img = get_field('pgm_lgtp_img',$course_id);
            }
            if ( get_field('pgm_mn',$course_id) ) {
                $pgm_mn = get_field('pgm_mn',$course_id);
            }
            if ( get_field('pgm_cor',$course_id) ) {
                $pgm_cor = get_field('pgm_cor',$course_id);
            }
            if ( get_field('pgn_fl_cmg',$course_id) ) {
                $pgn_fl_cmg = get_field('pgn_fl_cmg',$course_id);
            }
        }
        ?>

        <header class="curso-header mxmd:fixed mxmd:top-0 mxmd:left-0 mxmd:w-full bg-white relative z-[900]" style="--amr-pgm-cor: <?php if (isset($pgm_cor)) echo $pgm_cor; ?>;">
            <div class="relative z-[20] lg:w-[17.8vw] lg:w-[clamp(180px,17.8vw,300px)] md:px-[2.41vw] mxmd:pt-[6.66vh] md:pt-[2.77vh] pb-[3.88vh] curso-header-menu-wrapper">
                <button class="mxmd:hidden absolute left-[clamp(160px,15vw,230px)] top-[30px] curso-menu-toggle w-[40px] h-[40px] flex justify-center items-center"><span class="sr-only"><?php esc_attr_e('Expandir/Contrair o menu','amrwp'); ?></span>
                    <svg version="1.1" id="Layer_5" xmlns="http://www.w3.org/2000/svg" x="0" y="0" width="8" height="14.002" style="enable-background:new 0 0 8 14.002" xml:space="preserve"><path d="M.293 6.295a1 1 0 0 0 0 1.415l5.999 5.999a1 1 0 1 0 1.415-1.415L2.414 7.001l5.29-5.293A1 1 0 1 0 6.289.293L.29 6.292l.003.003z" style="fill:<?php if ( ! empty($pgm_cor) ) { echo $pgm_cor; } ?>"/></svg>
                </button>
                <button class="md:hidden mxmd:absolute mxmd:right-[8.33vw] mxmd:top-[6.66vh] btn-close btn-toggle-menu-mobile w-[40px] h-[40px] flex justify-center items-center"><span class="ball"></span><span class="sr-only"><?php esc_attr_e('Fechar o menu mobile','amrwp'); ?></span></button>
                <div class="flex flex-col h-full mxmd:items-center curso-header-menu-container">
                <?php
                if ( ! empty($pgm_lgtp_img_min) ) {
                    amrwp_img_tag_generate( $pgm_lgtp_img_min, 'full', 'max-w-full curso-header-logo-min mxmd:hidden', false );
                }
                if ( ! empty($pgm_lgtp_img) ) {
                    amrwp_img_tag_generate( $pgm_lgtp_img, 'full', 'max-w-full curso-header-logo', false );
                }
                if ( isset($pgm_mn) && has_nav_menu( $pgm_mn ) ) {
                ?>
                 <nav id="site-navigation-curso" class="mt-[5vh] mb-[3.33vh] curso-header-menu" aria-label="<?php esc_attr_e( 'Menu do curso Dinheiro Sem Medo', 'amrwp' ); ?>">
                    <?php
                        wp_nav_menu( array(
                            'theme_location' => $pgm_mn,
                            'menu_class'     => 'flex flex-col curso-header-menu-items',
                            'container'     => '',
                        ) );
                    ?>
                </nav>
                <?php
                }
                if ( $header_user_can_access && isset($pgn_fl_cmg) ) {
                ?>
                <a href="<?php echo get_permalink($pgn_fl_cmg); ?>" class="mt-auto mxmd:min-w-[160px] max-w-[12.8vw] py-[18px] rounded-[14px] flex flex-col items-center curso-header-fale-amuri <?php if ( $pgn_fl_cmg == $pageID ) echo 'current-page'; ?>">
                    <img class="curso-header-fale-amuri-image" src="<?php echo public_url() ?>images/amuri-fale-comigo.png" width="230" height="266" alt="">
                    <span class="btn-primary max-w-[115px] mt-[6px] btn"><?php esc_attr_e('Fale comigo','amrwp'); ?></span>
                </a>
                <?php } ?>
            </div>
            <!-- /.curso-header-menu-container -->
            </div>

            <div class="bg-white absolute md:fixed z-[10] gap-x-[17px] md:gap-x-[25px] top-0 left-0 h-[85px] mxmd:px-[25px] md:pr-[42px] py-[15px] w-full flex justify-end items-end md:items-center curso-header-top">
                <?php
                if ( ! empty($pgm_lgtp_img_min) ) {
                    amrwp_img_tag_generate( $pgm_lgtp_img_min, 'full', 'absolute top-[45px] left-[18px] max-w-full md:hidden curso-header-logo-min-mobile', false );
                }
                if ( $header_user_can_access ) include_once('includes/header-user-menu.php');
                if ( $course_id ) { ?>
                <button class="btn-toggle-menu-mobile btn-menu-hamburguer"><span></span><span class="txt"><?php esc_attr_e('Abrir menu','amrwp'); ?></span></button>
                <?php
                }
                ?>
            </div>
            <!-- /.curso-header-top -->
                

        </header>
        <!-- /.curso-header -->
