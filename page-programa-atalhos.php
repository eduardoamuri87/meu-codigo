<?php
/**
 * Template name: Atalhos do programa
 * Página com atalhos do programa
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

include_once( 'includes/user-can-access.php' );

global $post;
$pageID = $post->ID;

if ( function_exists('get_field') ) {

    if ( get_field('atl_prgm', $pageID) ) {
        $atl_prgm = get_field('atl_prgm', $pageID);
    }
    if ( get_field('pgm_msg_wlcm', $pageID) ) {
        $pgm_msg_wlcm = get_field('pgm_msg_wlcm', $pageID);
        $pgm_msg_wlcm = str_replace('{nome}',amrwp_get_user_name(),$pgm_msg_wlcm);
    }
    if ( get_field('pgm_msg_wlcm_img', $pageID) ) {
        $pgm_msg_wlcm_img = get_field('pgm_msg_wlcm_img', $pageID);
    }

    $course_id = amrpw_get_program_course_id();
    if ( ! empty($course_id) && get_field('pgm_cor',$course_id) ) {
        $pgm_cor = get_field('pgm_cor',$course_id);
    }
    
}

$assuntos = get_terms( array(
    'taxonomy'   => 'amr_plantao_assunto',
    'hide_empty' => true,
    'amr_custom_post_type' => 'amr_atalho'
) );

get_header('curso');
?>

<div class="mxmd:w-full mxxl:px-[1.6vw] pl-[3.29vw] pr-[3.29vw] mxmd:flex-col mxmd:flex flex-1 mxmd:pb-[40px] page-content-wrapper">
    <div class="mxmd:pb-[3.33vh] page-content-container">
        <div class="mxxl:pt-[20px] pt-[45px] md:w-[50.3vw] relative page-content-welcome mxmd:overflow-hidden">
            <?php if ( isset($pgm_msg_wlcm_img) ) { ?>
            <?php amrwp_img_tag_generate($pgm_msg_wlcm_img, 'full', 'page-content-welcome-image mxmd:w-[37.5vw] md:w-[14.5vw] h-auto absolute mxmd:bottom-[1.16vh] md:bottom-[1.9vh] mxmd:-right-[7vw] md:right-[1.8vw] z-[10]', false); ?>
            <?php } ?>
            <div class="page-content-welcome-text md:py-[5.87vh] md:pl-[2.19vw] md:pr-[20vw] relative z-[1]" <?php if ( ! empty($pgm_cor) ) { echo 'style="background-color:' . $pgm_cor . '"'; } ?>>
                <h1 class="leading-[1em] typog-title"><?php esc_attr_e('Atalhos','amrwp'); ?></h1>
                <?php if ( isset($pgm_msg_wlcm) ) { ?>
                <p class="mt-[15px] mxmd:pr-[18.5vw] md:max-w-[230px] typog-body-small"><?php echo $pgm_msg_wlcm; ?></p>
                <?php } ?>
            </div>
        </div>
        <!-- /.page-content-welcome -->
    </div>
    <!-- /.page-content-container -->

    <div class="page-nav-filter page-nav-filter-first page-nav-filter-wrapper md:mt-[25px]">
        <div class="filters mb-[20px] text-blue-dark md:inline-flex md:gap-x-[2.78vw] md:border-b-1 md:border-blue-dar">
            <a href="<?php echo get_permalink($pageID); ?>" class="text-blue-dark filter-link open-tab <?php if ( ! isset( $_REQUEST['assunto'] ) && ! isset($date_query) ) { echo 'active'; } ?>"><?php esc_attr_e('Todos','amrwp'); ?></a>
            <?php if ( isset ( $assuntos ) && ! empty($assuntos) ) {?>
            <button data-tabbutton="assunto" class="filter-link open-tab <?php if ( isset( $_REQUEST['assunto'] ) ) { echo 'active'; } else { if ( ! isset( $date_query ) ) { echo 'hide-mobile'; } } ?>"><?php esc_attr_e('Por assunto','amrwp'); ?></button>
            <?php } ?>
        </div>
        <!-- /.filter -->
        <div class="tabs">
        <?php if ( isset ( $assuntos ) && ! empty($assuntos) ) {?>
            <div data-tab-name="assunto" class="tab" <?php if ( isset( $_REQUEST['assunto'] ) ) { echo 'style="display:block;"'; } ?>>
                <div class="flex flex-wrap mxmd:pb-[20px] gap-x-[8px] gap-y-[12px]">
                    <?php
                    foreach ($assuntos as $assunto) {
                        if ( isset($_REQUEST['assunto']) && $assunto->slug == $_REQUEST['assunto'] ) {
                    ?>
                    <span class="btn-secondary active btn-term"><?php echo $assunto->name; ?></span>
                    <?php
                        } else {
                    ?>
                    <a class="btn-secondary btn-term" href="<?php echo get_permalink($pageID); ?>?assunto=<?php echo $assunto->slug; ?>"><?php echo $assunto->name; ?></a>
                    <?php
                        }
                    }
                    ?>
                    <button class="btn-show-more-terms ml-[20px] underline btn-reset-styles"><?php esc_attr_e('mostrar','amrwp'); ?> +</button>
                </div>
            </div>
        <?php } ?>
            
        </div>
    </div>
    <!-- /.page-nav-filter-wrapper -->

    <?php
    if ( isset($atl_prgm) ) {

        if ( isset( $_REQUEST['assunto'] ) ) {
            $tax_query = array(
                'relation' => 'AND',
                array(
                    'taxonomy' => 'amr_atalho_programa',
                    'field' => 'term_id',
                    'terms' => $atl_prgm
                ),
                array(
                    'taxonomy' => 'amr_plantao_assunto',
                    'field' => 'slug',
                    'terms' => $_REQUEST['assunto']
                ));
        } else {
            $tax_query = array(
                array(
                    'taxonomy' => 'amr_atalho_programa',
                    'field' => 'term_id',
                    'terms' => $atl_prgm
                ));
        }

        $atalhos_qry = new WP_Query(array(
            'post_type' => 'amr_atalho',
            'posts_per_page' => -1,
            'order' => 'ASC',
            'tax_query' => $tax_query
        ));
        if ( $atalhos_qry->have_posts() ): 
    ?>
        <div class="mxmd:px-[5vw] atalhos-grid">
    <?php
        $atalho_count = 0;
        $atalho_total = 0;
        while ( $atalhos_qry->have_posts() ): $atalhos_qry->the_post();
            if ( 7 == $atalho_count ) { $atalho_count = 0; }
            $atalho_count++;
            $atalho_total++;
            if ( 1 == $atalho_count ) {
            ?>
        <div class="cell-wrapper">
            <?php
            }
    ?>
            <article <?php post_class('cell'); ?>>
                <h2><a title="<?php echo get_the_title(); ?>" href="<?php the_permalink(); ?>"><span class="text"><?php the_title(); ?></span></a></h2>
            </article>
    <?php
            if ( 2 == $atalho_count ) {
            ?>
            <div class="cell box-1">
                <img src="<?php echo public_url(); ?>images/symbol-atalhos-30.svg" alt="" width="123" height="123">
            </div>
            <?php
            }
            if ( 3 == $atalho_count ) {
            ?>
            <div class="cell box-2">
                <img src="<?php echo public_url(); ?>images/symbol-atalhos-20.svg" alt="" width="123" height="123">
            </div>
            <?php
            }
            if ( 6 == $atalho_count ) {
            ?>
            <div class="cell box-3">
                <img src="<?php echo public_url(); ?>images/symbol-atalhos-10.svg" alt="" width="123" height="123">
            </div>
            <?php
            }
            if ( 7 == $atalho_count ) {
            ?>
            <div class="cell box-4">
                <img src="<?php echo public_url(); ?>images/symbol-atalhos-40.svg" alt="" width="123" height="123">
            </div>
        </div>
        <!-- /.cell-wrapper -->
            <?php
            }
            if ( 7 != $atalho_count && $atalho_total == $atalhos_qry->found_posts ) {
            ?>
        </div>
        <!-- /.cell-wrapper -->
            <?php
            }
        endwhile;
    ?>
    </div>
    <!-- /.atalhos-grid -->
    <?php
        else:
        ?>
        <p class="text-center my-[10vh] font-sans-black"><?php esc_attr_e('Desculpe, nenhum conteúdo encontrado!','amrwp'); ?></p>
        <?php
        endif;
        wp_reset_postdata();
    }
    ?>

    <div class="md:hidden mxmd:mt-[20px] page-nav-filter page-nav-filter-second page-nav-filter-wrapper md:mt-[25px]" <?php if ( isset($plnt_date) ) { ?>data-plantao-first-date="<?php echo $plnt_date; ?>"<?php } ?>>
        <div class="filters text-blue-dark md:inline-flex md:gap-x-[2.78vw] md:border-b-1 md:border-blue-dar">
            <?php if ( isset ( $assuntos ) && ! empty($assuntos) && ! isset( $_REQUEST['assunto'] ) ) {?>
            <button data-tabbutton="assunto2" class="filter-link open-tab <?php if ( isset( $_REQUEST['assunto'] ) ) { echo 'active'; } ?>"><?php esc_attr_e('Por assunto','amrwp'); ?></button>
            <?php } ?>
        </div>
        <!-- /.filter -->
        <div class="tabs">
        <?php if ( isset ( $assuntos ) && ! empty($assuntos) && ! isset( $_REQUEST['assunto'] ) ) {?>
            <div data-tab-name="assunto2" class="tab" <?php if ( isset( $_REQUEST['assunto'] ) ) { echo 'style="display:block;"'; } ?>>
                <div class="pt-[20px] flex flex-wrap gap-x-[8px] gap-y-[12px]">
                    <?php
                    foreach ($assuntos as $assunto) {
                        if ( isset($_REQUEST['assunto']) && $assunto->slug == $_REQUEST['assunto'] ) {
                    ?>
                    <span class="btn-secondary active btn-term"><?php echo $assunto->name; ?></span>
                    <?php
                        } else {
                    ?>
                    <a class="btn-secondary btn-term" href="<?php echo get_permalink($pageID); ?>?assunto=<?php echo $assunto->slug; ?>"><?php echo $assunto->name; ?></a>
                    <?php
                        }
                    }
                    ?>
                    <button class="btn-show-more-terms ml-[20px] underline btn-reset-styles"><?php esc_attr_e('mostrar','amrwp'); ?> +</button>
                </div>
            </div>
        <?php } ?>
        </div>
    </div>


</div>
<!-- /.page-content -->

<?php get_footer(); ?>