<?php
/**
 * Template name: Consultoria
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

include_once( 'includes/user-can-access.php' );

global $post;
$pageID = $post->ID;

if ( function_exists('get_field') ) {

    if ( get_field('cnstr_prgm', $pageID) ) {
        $cnstr_prgm = get_field('cnstr_prgm', $pageID);
    }

    if ( get_field('cnstr_msg_wlcm', $pageID) ) {
        $cnstr_msg_wlcm = get_field('cnstr_msg_wlcm', $pageID);
    }

    if ( get_field('cnstr_msg_wlcm_img', $pageID) ) {
        $cnstr_msg_wlcm_img = get_field('cnstr_msg_wlcm_img', $pageID);
    }

    if ( get_field('cnstr_clndr_cd', $pageID) ) {
        $cnstr_clndr_cd = get_field('cnstr_clndr_cd', $pageID);
    }
   
    $course_id = amrpw_get_program_course_id();
    if ( ! empty($course_id) && get_field('pgm_cor',$course_id) ) {
        $pgm_cor = get_field('pgm_cor',$course_id);
    }
 
}

get_header('curso');
?>

<div class="mxlg:w-full mxxl:px-[1.6vw] pl-[3.29vw] pr-[3.29vw] mxlg:flex-col mxlg:flex flex-1 pb-[40px] page-content-wrapper">
    <div class="mxlg:pb-[3.33vh] page-content-container lg:flex">
        <div class="page-content-welcome mxxl:pt-[20px] pt-[45px] mxlg:overflow-hidden lg:flex-1">
            <div class="relative">
                <?php if ( isset($cnstr_msg_wlcm_img) ) { ?>
                    <?php amrwp_img_tag_generate($cnstr_msg_wlcm_img, 'full', 'page-content-welcome-image mxlg:w-[37.5vw] lg:w-[17.56vw] h-auto absolute mxlg:bottom-[1.16vh] lg:bottom-[50%] lg:translate-y-[35%] mxlg:-right-[7vw] lg:right-[1.8vw] z-[10]', false); ?>
                <?php } ?>
                <div class="page-content-welcome-text lg:pt-[35px] lg:pb-[50px] lg:pl-[2.19vw] lg:pr-[20vw] relative z-[1]" <?php if ( ! empty($pgm_cor) ) { echo 'style="background-color:' . $pgm_cor . '"'; } ?>>
                    <h1 class="leading-[1em] typog-title"><?php esc_attr_e('Consultoria','amrwp'); ?></h1>
                    <?php if ( isset($cnstr_msg_wlcm) ) { ?>
                    <p class="mt-[15px] lg:max-w-[330px] typog-body-small"><?php echo $cnstr_msg_wlcm; ?></p>
                    <?php } ?>
                </div>
            </div>
            <!-- /.page-content-welcome -->

            <div class="editor-content py-[30px] mxmd:px-[4.16vw]">

                <?php
                while ( have_posts() ): the_post();
                    the_content();
                endwhile;
                ?>
            </div>

        </div>
        
        
        <div class="lg:w-[23.6vw] lg:min-w-[323px] lg:pl-[2.92vw] lg:pt-[20px] xl:pt-[45px] sidebar-calendar">
            <?php if ( isset($cnstr_clndr_cd) ) { ?>
            <div class="widget calendar h-[500px]">
                <?php echo $cnstr_clndr_cd; ?>
            </div>
            <?php } ?>
        </div>

    </div>
    <!-- /.page-content-container -->

</div>
<!-- /.page-content -->

<?php get_footer(); ?>