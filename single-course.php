<?php
/**
 * Single post do curso
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

include_once( 'includes/user-can-access.php' );

global $post;
$course_id = $post->ID;

if ( function_exists('get_field') ) {

    if ( get_field('pgm_cor',$course_id) ) {
        $pgm_cor = get_field('pgm_cor',$course_id);
    }

    if ( get_field('pgm_ilustra',$course_id) ) {
        $pgm_ilustra = get_field('pgm_ilustra',$course_id);
    }

    if ( get_field('pgm_wlcm_msg',$course_id) ) {
        $pgm_wlcm_msg = get_field('pgm_wlcm_msg',$course_id);
    }

    if ( get_field('pgm_wlcm_submsg',$course_id) ) {
        $pgm_wlcm_submsg = get_field('pgm_wlcm_submsg',$course_id);
    }
    
}

get_header('curso');
?>
<div class="mxmd:w-full mxxl:px-[1.6vw] px-[3.29vw] mxmd:flex-col mxmd:flex flex-1 page-content-wrapper aabbc">
    <div class="mxmd:pb-[3.33vh] md:flex page-content-container">
        <div class="mxmd:overflow-hidden md:flex-1 md:w-[48.8vw] md:mt-[20px] xl:mt-[45px] page-content-welcome-text relative md:pt-[40px] md:pb-[20px] md:pl-[2.19vw] md:pr-[20vw] relative z-[1]" <?php if ( ! empty($pgm_cor) ) { echo 'style="background-color:' . $pgm_cor . '"'; } ?>>
            <?php if ( isset($pgm_ilustra) ) { ?>
            <?php amrwp_img_tag_generate($pgm_ilustra, 'full', 'page-content-welcome-image mxmd:w-[37.5vw] md:w-auto md:h-[120%] absolute z-1 mxmd:bottom-0 md:bottom-0 mxmd:-right-[28vw] md:right-0 z-[10]', false); ?>
            <?php } ?>
        
            <?php if ( isset($pgm_wlcm_msg) ) { ?>
            <h1 class="mxmd:max-w-[75vw] relative z-10 leading-[1.1em] typog-title"><?php echo $pgm_wlcm_msg; ?></h1>
            <?php } ?>
            <?php if ( isset($pgm_wlcm_submsg) ) { ?>
            <p class="relative z-10 mt-[15px] mxmd:pr-[18.5vw] typog-body-small"><?php echo $pgm_wlcm_submsg; ?></p>
            <?php } ?>
        </div>
        
        <div class="md:w-[23vw] mxmd:w-full md:pl-[3.29vw] md:mt-[20px] xl:mt-[45px]">
            <?php include('template-parts/widget-proxima-aula.php'); ?>
        </div>
    </div>
    <!-- /.page-content-container -->

    <section class="mxmd:mx-[5.55vw] md:pt-[9vh] course-lessons">
        <?php include('template-parts/widget-estrutura-curso.php'); ?>
    </section>


</div>
<!-- /.page-content -->

<?php get_footer(); ?>