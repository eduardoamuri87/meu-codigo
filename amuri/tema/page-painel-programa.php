<?php
/**
 * Template name: Painel do programa
 * Página com o painel do programa
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

include_once( 'includes/user-can-access.php' );

global $post;
$pageID = $post->ID;

if ( function_exists('get_field') ) {
    
    if ( get_field('pgm_msg_wlcm', $pageID) ) {
        $pgm_msg_wlcm = get_field('pgm_msg_wlcm', $pageID);
        $pgm_msg_wlcm = str_replace('{nome}',amrwp_get_user_name(),$pgm_msg_wlcm);
    }
    if ( get_field('pgm_msg_wlcm_sub', $pageID) ) {
        $pgm_msg_wlcm_sub = get_field('pgm_msg_wlcm_sub', $pageID);
        $pgm_msg_wlcm_sub = str_replace('{nome}',amrwp_get_user_name(),$pgm_msg_wlcm_sub);
    }
    if ( get_field('pgm_msg_wlcm_img', $pageID) ) {
        $pgm_msg_wlcm_img = get_field('pgm_msg_wlcm_img', $pageID);
    }
    if ( get_field('pgm_recds', $pageID) ) {
        $pgm_recds = get_field('pgm_recds', $pageID);
    }
    if ( get_field('pgm_plnt', $pageID) ) {
        $pgm_plnt = get_field('pgm_plnt', $pageID);
    }
    $course_id = amrpw_get_program_course_id();
    if ( ! empty($course_id) && get_field('pgm_cor',$course_id) ) {
        $pgm_cor = get_field('pgm_cor',$course_id);
    }
}

get_header('curso');
?>

<?php if ( isset($pgm_cor) ) { ?>
    <style>
        .recados-plantoes-slider-wrapper {
            --pgm-cor: <?php echo $pgm_cor; ?>;
        }
        .recados-plantoes-slider-wrapper .btn-arrow path { fill: var(--pgm-cor) !important; }
        .recados-plantoes-slider-wrapper .slick-dots > li { background-color: var(--pgm-cor) !important; }
    </style>
<?php } ?>

<div class="mxmd:w-full mxxl:px-[1.6vw] px-[3.29vw] mxmd:flex-col flex md:flex-1 page-content-wrapper">

    <div class="mxmd:pb-[4.1vh] md:pb-[40px] flex-1 page-content-container">
        <div class="mxxl:pt-[20px] pt-[3.29vw] relative page-content-welcome">
            <?php if ( isset($pgm_msg_wlcm_img) ) { ?>
            <?php amrwp_img_tag_generate($pgm_msg_wlcm_img, 'full', 'mxmd:hidden page-content-welcome-image md:w-[clamp(150px,20.1vw,275px)] md:max-w-[250px] md:h-auto md:ml-auto md:absolute md:bottom-0 md:right-0 md:z-[10]', false); ?>
            <?php } ?>
            <div class="page-content-welcome-text md:py-[40px] md:pl-[2.19vw] md:pr-[25.5vw] relative z-[1]" <?php if ( ! empty($pgm_cor) ) { echo 'style="background-color:' . $pgm_cor . '"'; } ?>>
                <?php if ( isset($pgm_msg_wlcm) ) { ?>
                <h1 class="leading-[1em] typog-title"><?php echo $pgm_msg_wlcm; ?></h1>
                <?php } ?>
                <?php if ( isset($pgm_msg_wlcm_sub) ) { ?>
                <p class="mt-[15px] typog-body-small"><?php echo $pgm_msg_wlcm_sub; ?></p>
                <?php } ?>
            </div>
        </div>
        <!-- /.page-content-welcome -->
        <div class="mxmd:mt-[3.33vh] mxmd:px-[5vw] md:mt-[30px] editor-content">
            <div class="editor-text-expand">
                <?php
                while ( have_posts() ): the_post();
                    the_content();
                endwhile;
                ?>
            </div>
            <!-- /.editor-text-expand -->
            <button class="text-expand-toggle"><?php esc_attr_e('mostrar +','amrwp'); ?></button>
        </div>
    </div>
    <!-- /.page-content -->

    <div class="ml-auto pl-[2.92vw] md:w-[23.42vw] mxxl:pt-[20px] md:min-w-[200px] pt-[3.29vw] mxxl:pl-[1.45vw] page-sidebar">
        <?php if ( ! empty($pgm_recds) ) { ?>
        <div class="widget recados py-[30px] px-[2.9vw] bg-white">
            <h3 class="px-[12px] flex leading-1em typog-title-med"><?php esc_attr_e('Recados do Amuri','amrwp'); ?> <svg class="lg:hidden xl:block relative -top-[4px] ml-[12px]" version="1.1" id="Layer_7" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px"
	 width="18.658px" height="21.323px" viewBox="0 0 18.658 21.323" style="enable-background:new 0 0 18.658 21.323;"
	 xml:space="preserve">
<path class="st2" d="M9.329,21.323c1.471,0,2.664-1.193,2.664-2.665H6.665C6.665,20.13,7.858,21.323,9.329,21.323z M18.299,15.088
	c-0.805-0.865-2.31-2.165-2.31-6.426c0-3.236-2.269-5.826-5.328-6.462V1.333C10.661,0.597,10.064,0,9.329,0S7.997,0.597,7.997,1.333
	v0.868C4.938,2.836,2.669,5.427,2.669,8.663c0,4.26-1.506,5.561-2.31,6.426c-0.25,0.269-0.361,0.59-0.359,0.904
	c0.005,0.683,0.541,1.333,1.337,1.333h15.984c0.796,0,1.333-0.65,1.337-1.333C18.66,15.678,18.549,15.357,18.299,15.088z"/>
</svg></h3>
            <div class="mt-[10px] recados-plantoes-slider-wrapper recados-slider-wrapper">
                <button class="btn-arrow arrow-prev -translate-x-[10px]">
                    <svg version="1.1" id="Layer_7" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px"
                        width="8px" height="14.002px" viewBox="0 0 8 14.002" style="enable-background:new 0 0 8 14.002;" xml:space="preserve">
                    <path class="st4" d="M0.293,6.295c-0.391,0.391-0.391,1.025,0,1.415l5.999,5.999c0.391,0.391,1.025,0.391,1.415,0
                        s0.391-1.025,0-1.415L2.414,7.001l5.29-5.293c0.391-0.391,0.391-1.025,0-1.415s-1.025-0.391-1.415,0L0.29,6.292L0.293,6.295z"/>
                    </svg>
                </button>
                <div class="recados-plantoes-slider recados-slider">
            <?php foreach ($pgm_recds as $pgm_recd) { ?>
                <?php include('template-parts/recados-audio-player.php') ?>
            <?php } ?>   
                </div> 
            <button class="btn-arrow arrow-next translate-x-[10px] ">
                    <svg version="1.1" id="Layer_7" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px"
                        width="8px" height="14.002px" viewBox="0 0 8 14.002" style="enable-background:new 0 0 8 14.002;" xml:space="preserve">
                    <path class="st4" d="M0.293,6.295c-0.391,0.391-0.391,1.025,0,1.415l5.999,5.999c0.391,0.391,1.025,0.391,1.415,0
                        s0.391-1.025,0-1.415L2.414,7.001l5.29-5.293c0.391-0.391,0.391-1.025,0-1.415s-1.025-0.391-1.415,0L0.29,6.292L0.293,6.295z"/>
                    </svg>
                </button>
            </div>
        </div>
        <?php } // if ( ! empty($pgm_recds) ) { ?>
        
        <?php if ( ! empty($pgm_plnt) ) { ?>
        <?php include('template-parts/widget-proximos-plantoes.php'); ?>
        <?php } // if ( ! empty($pgm_plnt) ) { ?>
        
        <div class="md:mt-[20px]">
            <?php include('template-parts/widget-proxima-aula.php'); ?>
        </div>
    </div>
    <!-- /.page-sidebar -->

</div>
<!-- /.page-content -->

<?php get_footer(); ?>