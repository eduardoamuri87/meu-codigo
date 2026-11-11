<?php
/**
 * Template name: Plantoes do programa
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

include_once( 'includes/user-can-access.php' );

global $post;
$pageID = $post->ID;

if ( function_exists('get_field') ) {

    if ( get_field('plnt_prgm', $pageID) ) {
        $plnt_prgm = get_field('plnt_prgm', $pageID);
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

    if ( isset( $post->post_parent ) && get_field('pgm_plnt', $post->post_parent) ) {
        $pgm_plnt = get_field('pgm_plnt', $post->post_parent);
    }
    
}

$plnt_post_type = 'amr_plantao';

get_header('curso');
?>

<div class="mxmd:w-full mxxl:px-[1.6vw] pl-[3.29vw] pr-[3.29vw] mxmd:flex-col mxmd:flex flex-1 pb-[40px] page-content-wrapper">
    <div class="mxmd:pb-[3.33vh] page-content-container md:flex">
        <div class="mxxl:pt-[20px] pt-[45px] relative page-content-welcome mxmd:overflow-hidden md:flex-1">
            <?php if ( isset($pgm_msg_wlcm_img) ) { ?>
            <?php amrwp_img_tag_generate($pgm_msg_wlcm_img, 'full', 'page-content-welcome-image mxmd:w-[37.5vw] md:w-[17.56vw] h-auto absolute mxmd:bottom-[1.16vh] md:bottom-[50%] md:translate-y-[50%] mxmd:-right-[7vw] md:right-[1.8vw] z-[10]', false); ?>
            <?php } ?>
            <div class="h-full page-content-welcome-text md:py-[5.87vh] md:pl-[2.19vw] md:pr-[20vw] relative z-[1]" <?php if ( ! empty($pgm_cor) ) { echo 'style="background-color:' . $pgm_cor . '"'; } ?>>
                <h1 class="leading-[1em] typog-title"><?php esc_attr_e('Plantões','amrwp'); ?></h1>
                <?php if ( isset($pgm_msg_wlcm) ) { ?>
                <p class="mt-[15px]  md:max-w-[330px] typog-body-small"><?php echo $pgm_msg_wlcm; ?></p>
                <?php } ?>
            </div>
        </div>
        <!-- /.page-content-welcome -->
        <?php if ( ! empty($pgm_plnt) ) { ?>
        <div class="md:w-[23.42vw] md:min-w-[200px] md:pl-[2.92vw] lg:pt-[20px] xl:pt-[25px]">
        <?php include('template-parts/widget-proximos-plantoes.php'); ?>
        </div>
        <?php } // if ( ! empty($pgm_plnt) ) { ?>
    </div>
    <!-- /.page-content-container -->

    <?php
    if ( isset($_REQUEST['plantaoFrom']) && isset($_REQUEST['plantaoTo']) ) {
        $plantaoFrom = explode('/',$_REQUEST['plantaoFrom']) ;
        $plantaoTo = explode('/',$_REQUEST['plantaoTo']);

        if ( count($plantaoFrom) == 3 && count($plantaoTo) == 3 && checkdate($plantaoFrom[1],$plantaoFrom[0],$plantaoFrom[2]) && checkdate($plantaoTo[1],$plantaoTo[0],$plantaoTo[2]) ) {

            $date_query = array(
                array(
                    'after'     => array(
                        'day' => $plantaoFrom[0],
                        'month' => $plantaoFrom[1],
                        'year' => $plantaoFrom[2],
                    ),
                    'before' => array(
                        'day' => $plantaoTo[0],
                        'month' => $plantaoTo[1],
                        'year' => $plantaoTo[2],
                    ),
                    'inclusive' => true,
                ),
            );
        
        }

    }
    if ( isset( $_REQUEST['assunto'] ) ) {
        $plnt_post_type = 'amr_plantao_duvida';
        $tax_query = array(
            'relation' => 'AND',
            array(
                'taxonomy' => 'amr_atalho_programa',
                'field' => 'term_id',
                'terms' => $plnt_prgm
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
                'terms' => $plnt_prgm
            ));
    }
    

    if ( isset($plnt_prgm) ) {
        $plantoes_qry__first_arr = array(
            'post_type' => 'amr_plantao',
            'posts_per_page' => 1,
            'order' => 'ASC',
            'orderby' => 'DATE',
            'tax_query' => array(
                array(
                    'taxonomy' => 'amr_atalho_programa',
                    'field' => 'term_id',
                    'terms' => $plnt_prgm
                ))
        );

        $plantoes_qry_first = new WP_Query($plantoes_qry__first_arr);
        if ( $plantoes_qry_first->have_posts() ): 
            while ( $plantoes_qry_first->have_posts() ): $plantoes_qry_first->the_post();
                $plnt_date = get_the_date( 'd/m/Y'  );
            endwhile;
        endif;
        wp_reset_postdata();

        $paged = ( get_query_var( 'paged' ) ) ? get_query_var( 'paged' ) : 1;
        $plantoes_qry_arr = array(
            'post_type' => $plnt_post_type,
            'posts_per_page' => 12,
            'paged' => $paged,
            'order' => 'DESC',
            'orderby' => 'DATE',
            'tax_query' => $tax_query
        );

        if ( isset($date_query) ) {
            $plantoes_qry_arr['date_query'] = $date_query;
        }
        ?>


    <?php
    $assuntos = get_terms( array(
        'taxonomy'   => 'amr_plantao_assunto',
        'hide_empty' => true,
        'amr_custom_post_type' => 'amr_plantao_duvida'
    ) );
    ?>

    <div class="page-nav-filter page-nav-filter-first page-nav-filter-wrapper md:mt-[25px]" <?php if ( isset($plnt_date) ) { ?>data-plantao-first-date="<?php echo $plnt_date; ?>"<?php } ?>>
        <div class="filters mb-[20px] text-blue-dark md:inline-flex md:gap-x-[2.78vw] md:border-b-1 md:border-blue-dar">
            <a href="<?php echo get_permalink($pageID); ?>" class="text-blue-dark filter-link open-tab <?php if ( ! isset( $_REQUEST['assunto'] ) && ! isset($date_query) ) { echo 'active'; } ?>"><?php esc_attr_e('Todos','amrwp'); ?></a>
            <?php if ( isset ( $assuntos ) && ! empty($assuntos) ) {?>
            <button data-tabbutton="assunto" class="filter-link open-tab <?php if ( isset( $_REQUEST['assunto'] ) ) { echo 'active'; } else { if ( ! isset( $date_query ) ) { echo 'hide-mobile'; } } ?>"><?php esc_attr_e('Por assunto','amrwp'); ?></button>
            <?php } ?>
            <button data-tabbutton="data" class="filter-link open-tab <?php if ( isset($date_query) ) { echo 'active'; } else { echo 'hide-mobile'; } ?>"><?php esc_attr_e('Por data','amrwp'); ?></button>
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
            <div data-tab-name="data" class="tab" <?php if ( isset($date_query) ) { echo 'style="display:block;"'; } ?>>
                <form action="">
                    <div class="tab-date md:items-center mxmd:pb-[20px] md:flex md:gap-x-[8px] md:items-center">
                        <span class="items-center md:flex md:gap-x-[8px] mxmd:flex mxmd:gap-x-[6px]">Data <label for="plantaoFrom"><?php esc_attr_e('entre','amrwp'); ?> </label> <input autocomplete="off" type="text" id="plantaoFrom" name="plantaoFrom" value="<?php if ( isset($_REQUEST['plantaoFrom']) ) { echo $_REQUEST['plantaoFrom']; } ?>"> <label for="plantaoTo"><?php esc_attr_e('e','amrw'); ?></label> <input autocomplete="off" type="text" id="plantaoTo" name="plantaoTo" value="<?php if ( isset($_REQUEST['plantaoTo']) ) { echo $_REQUEST['plantaoTo']; } ?>"></span> <button type="submit" class="mxmd:mt-[10px] btn-primary" <?php if ( !isset($date_query) ) { echo 'disabled="disabled"'; } ?>><?php esc_attr_e('Buscar','amrwp'); ?></button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <!-- /.page-nav-filter-wrapper -->

    <?php
    if ( isset( $_REQUEST['assunto'] ) ) {
        $term_plantao = get_term_by('slug',$_REQUEST['assunto'],'amr_plantao_assunto');
        if ( $term_plantao ) {
        ?>
        <p class="mxmd:px-[4.16vw] mt-[40px] text-[16px] plantao-page-term">&gt; <?php esc_attr_e('Plantões com o assunto','amrwp'); ?> "<?php echo $term_plantao->name; ?>"</p>
        <?php
        }
    }
    ?>

        <?php
        $plantoes_qry = new WP_Query($plantoes_qry_arr);
        if ( $plantoes_qry->have_posts() ): 
            if ( isset($date_query) ) {
            ?>
            <p class="mxmd:px-[4.16vw] mxmd:pb-[40px] mt-[40px] text-[16px] plantao-page-term">&gt; <?php esc_attr_e('Resultado da busca:','amrwp'); ?></p>
            <?php
            }
    ?>
        <div class="plantoes-grid-posts" data-post-type="<?php echo $plnt_post_type; ?>" <?php if ( isset( $plnt_prgm ) ) { ?>data-term-programa="<?php echo $plnt_prgm[0]; ?>"<?php } ?> <?php if ( isset( $_REQUEST['assunto'] ) ) { ?>data-term-assunto="<?php echo $_REQUEST['assunto']; ?>"<?php } ?>>
            <div class="mxmd:px-[5vw] md:mt-[25px] plantoes-grid <?php if ( isset( $_REQUEST['assunto'] ) ) { echo ' listing-term'; } ?>" data-action="amrwp_load_plantoes" data-nonce="<?php echo wp_create_nonce("amrwp_load_plantoes"); ?>">
    <?php
        while ( $plantoes_qry->have_posts() ): $plantoes_qry->the_post();
            include('template-parts/plantao-post.php');
        endwhile;
    ?>
      
            <div class="plantoes-pagination-wrapper">
            <?php amrwp_paging_nav( $plantoes_qry->max_num_pages, $paged ); ?>
            </div>
        </div>
        <!-- /.atalhos-grid -->
    </div>
    <!-- /.plantoes-grid-posts -->
    <?php if ( $plantoes_qry->max_num_pages > 1 ) { ?>
    <div class="posts-load-more">
        <button class="underline btn-show-more-plantoes">mostrar +</button>
        <span class="loading"><?php esc_attr_e('carregando...','amrwp'); ?></span>
    </div>
    <!-- /.posts-load-more -->
    <?php } ?>
    <?php
        else:
    ?>
        <p class="mt-[40px] mxmd:px-[4.16vw]"><?php esc_attr_e('Nenhum resultado encontrado.','amrwp'); ?></p>
    <?php
        endif;
        wp_reset_postdata();
    }
    ?>


    <?php if ( ! isset( $date_query ) ) { ?>
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

    <div class="md:hidden mxmd:mt-[20px] page-nav-filter page-nav-filter-third page-nav-filter-wrapper md:mt-[25px]" <?php if ( isset($plnt_date) ) { ?>data-plantao-first-date="<?php echo $plnt_date; ?>"<?php } ?>>

        <div class="filters mb-[20px] text-blue-dark md:inline-flex md:gap-x-[2.78vw] md:border-b-1 md:border-blue-dar">
            <button data-tabbutton="data" class="filter-link open-tab <?php if ( isset($date_query) ) { echo 'active'; } ?>"><?php esc_attr_e('Por data','amrwp'); ?></button>
        </div>
        <div class="tabs">
        </div>
    </div>
    <?php } ?>

</div>
<!-- /.page-content -->

<div class="single-plantao-wrapper w-screen h-screen fixed top-0 left-0 z-900">
    <div class="overlay absolute top-0 left-0 bg-blue-dark bg-opacity-[80%] w-full h-full"></div>
    <div class="post-overlay opacity-0 scale-[.8] md:w-[90vw] lg:w-[62.9vw] h-screen rounded-[10px] bg-orange-light absolute top-0 left-1/2 -translate-x-1/2 transition-all duration-[300ms]">
        <div class="single-content">
            <button class="btn-close"><?php esc_attr_e('Fechar','amrwp'); ?></button>
            <span class="loading"><?php esc_attr_e('carregando...','amrwp'); ?></span>
            <div class="post-content"></div>
        </div>
    </div>

</div>
<!-- /.single-plantao-wrapper -->


<?php get_footer(); ?>