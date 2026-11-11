<?php
/**
 * Template para as lições
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

include_once( 'includes/user-can-access.php' );

global $post;
$pageID = $post->ID;
if ( is_singular('lesson') ) {
    $current_lesson_id = $post->ID;
}
$course_id = (int)get_post_meta( $pageID, '_lesson_course', true );

if ( function_exists('get_field') ) {

    if ( isset($course_id) && get_field('pgm_cor',$course_id) ) {
        $pgm_cor = get_field('pgm_cor',$course_id);
    ?>
    <style>
        body.single-lesson .course-progress-line,
        body.single-lesson .mCSB_dragger_bar {background-color:<?php echo $pgm_cor; ?> !important;}
    </style>
    <?php
    }

    if ( $user_can_access && get_field('lssn_vdo', $pageID) ) {
        $lssn_vdo = get_field('lssn_vdo', $pageID);
    }

    if ( $user_can_access && get_field('lssn_vdo_embed', $pageID) ) {
        $lssn_vdo_embed = get_field('lssn_vdo_embed', $pageID);
    }

    if ( $user_can_access && have_rows('lssn_mtrs', $pageID) ) {
        $lssn_mtrs = get_field('lssn_mtrs', $pageID);
    }
    
}

get_header('curso');

while ( have_posts() ): the_post();
?>

<div class="mxmd:w-full mxxl:px-[1.6vw] px-[3.29vw] mxmd:flex-col flex md:flex-1 page-content-wrapper">
    <div class="mxmd:mt-[3.33vh] mxmd:px-[5vw] pt-[3.29vw] mxmd:pb-[3.33vh] pb-[30px] flex-1 page-content-container">
        <h1 class="typog-title-g"><?php the_title(); ?></h1>

        <?php
        $the_content = apply_filters('the_content', get_the_content());
        if ( $user_can_access && ! empty($lssn_vdo_embed) ) {
        ?>
        <div class="mt-[20px] video-wrapper"><?php echo $lssn_vdo_embed; ?></div>
        <?php
        }
        ?>

        <div class="mxmd:mt-[30px] md:mt-[20px] md:pb-[30px] content-tabs-wrapper">
            <ul id="tabs" class="mxmd:hidden link-tabs flex tabs gap-x-[2.92vw]">
                <?php if ( ! empty($the_content) ) { ?>
                <li class="tab"><a href="#sobre"><?php esc_attr_e('Sobre','amrwp'); ?></a></li>
                <?php } ?>
                <?php if ( ! empty($lssn_mtrs) ) { ?>
                <li class="tab"><a href="#material-complementar"><?php esc_attr_e('Material Complementar','amrwp'); ?></a></li>
                <?php } ?>
            </ul>
            <ul class="mt-[20px] content-tabs">
                <li id="sobre">
                    <div>
                        <h2 class="md:hidden title"><button class="btn-reset-styles btn-toggle-content"><?php esc_attr_e('Sobre','amrwp'); ?></button></h2>
                        <div class="mxmd:text-[17px] content editor-content pb-[30px]">
                            <?php if ( $user_can_access ) { ?>
                                <?php if ( ! empty($the_content) ) { the_content(); } ?>
                            <?php } else { ?>
                                <?php esc_attr_e('O conteúdo dessa aula é exclusivo para alunos matriculados.','amrwp'); ?> <br>
                                <?php esc_attr_e('Se você já se matriculou','amrwp'); ?> <a href="<?php echo get_permalink( get_option('woocommerce_myaccount_page_id') ); ?>"> <?php esc_attr_e('basta efetuar o login','amrwp'); ?></a>.
                            <?php } ?>
                        </div>
                    </div>
                </li>
                <?php if ( ! empty($lssn_mtrs) ) { ?>
                <li id="material-complementar">
                    <div>
                        <h2 class="md:hidden title"><button class="btn-reset-styles btn-toggle-content"><?php esc_attr_e('Material Complementar','amrwp'); ?></button></h2>
                        <div class="flex flex-col gap-y-[20px] content">
                        <?php
                        foreach ($lssn_mtrs as $material) {
                            if ( $material['lssn_mtrs_lnk'] ) {
                                $aula_link = $material['lssn_mtrs_lnk'];
                                if ( $aula_link['title'] && $aula_link['url'] ) {
                            ?>
                        <a class="[&:not(:first-child)]:mt-[16px] resource-item-link material-link-type-<?php if ( isset( $material['lssn_mtrs_tp'] )  ) { echo $material['lssn_mtrs_tp']; } ?>" <?php if ( $aula_link['target'] ) echo 'target="' . $aula_link['target'] . '"'; ?> href="<?php echo $aula_link['url']; ?>" class="link-material">
                                <p class="resource-item-name">
                                <?php
                                if ( isset( $material['lssn_mtrs_tp'] ) ) {
                                    if ( 'video' == $material['lssn_mtrs_tp'] ) echo __( 'Vídeo', 'amrwp' );
                                    if ( 'livro' == $material['lssn_mtrs_tp'] ) echo __( 'Livro', 'amrwp' );
                                    if ( 'texto' == $material['lssn_mtrs_tp'] ) echo __( 'Texto', 'amrwp' );
                                    if ( 'arquivo' == $material['lssn_mtrs_tp'] ) echo __( 'Arquivo', 'amrwp' );
                                    if ( 'podcast' == $material['lssn_mtrs_tp'] ) echo __( 'Podcast', 'amrwp' );
                                }
                                ?>
                                </p>
                                <h3 class="resource-item-title"><?php echo $aula_link['title']; ?></h3>
                                <?php if ( $material['lssn_mtrs_txt'] ) { ?>
                                <p class="resource-item-desc"><?php echo $material['lssn_mtrs_txt']; ?></p>
                                <?php } ?>
                        </a>
                            <?php
                                }
                            }
                        ?>
                            
                        <?php
                        }
                        ?>
                        </div>
                    </div>
                </li>
                <?php } ?>
            </ul>

            <?php
            if ( $user_can_access && class_exists('Sensei_Frontend') ) {
                (new Sensei_Frontend)->sensei_complete_lesson_button();
            }
            ?>
        </div>
        <!-- /.content-tabs-wrapper -->

    </div>
    <!-- /.page-content-container -->

    <div class="mxmd:px-[5vw] md:pt-[3.29vw] md:ml-auto md:pl-[2.92vw] md:w-[23.42vw] md:min-w-[200px] page-sidebar">
    <?php
    if ( $user_can_access && class_exists('Sensei_Course') ) {
        if ( isset( $course_id ) ) {
            $course_progress = (new Sensei_Course)->get_progress_stats($course_id);
            if ( ! empty($course_progress) && isset($course_progress['completed_lessons_percentage']) ) {
    ?>
        <style>
            .course-progress-line {width:<?php echo $course_progress['completed_lessons_percentage']; ?>%;}
        </style>
        <div class="widget aula w-full mxmd:py-[28px] mxmd:px-[6.66vw] md:py-[35px] md:px-[2vw] bg-white">
            <h2 class="flex leading-1em typog-title-med"><?php esc_attr_e('Seu progresso','amrwp'); ?></h2>
            <div class="course-progress">
                <div class="mt-[20px] h-[23px] bg-orange-light rounded-[12px] relative overflow-hidden course-progress-bar">
                    <span class="relative z-1 rounded-[12px] course-progress-line h-full block"></span>
                    <span class="absolute z-10 top-1/2 right-[16px] -translate-y-1/2 text-[16px] course-progress-number"><?php echo $course_progress['completed_lessons_percentage']; ?>%</span>
                </div>
            </div>
            <!-- /.course-progress -->
        </div>
            <?php
            }
        }
    }
    ?>
        <div class="widget pb-[30px] course-lessons">
            <?php include('template-parts/widget-estrutura-curso.php'); ?>
        </div>
        <!-- /.widget course-lessons -->
    </div>

</div>
<!-- /.page-content -->

<?php
endwhile; // while ( have_posts() ): the_post();
get_footer();
?>