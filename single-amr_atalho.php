<?php
/**
 * Template para os posts de Atalhos
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

include_once( 'includes/user-can-access.php' );

global $post;
$pageID = $post->ID;

if ( function_exists('get_field') ) {

    if ( get_field('atl_vdo_embed', $pageID) ) {
        $atl_vdo_embed = get_field('atl_vdo_embed', $pageID);
    }

    if ( get_field('atl_als', $pageID) ) {
        $atl_als = get_field('atl_als', $pageID);
    }
    
    if ( have_rows('atl_mtrs', $pageID) ) {
        $atl_mtrs = get_field('atl_mtrs', $pageID);
    }
    
}

get_header('curso');

while ( have_posts() ): the_post();
?>

<div class="mxmd:w-full mxxl:px-[1.6vw] pl-[3.29vw] pr-[3.29vw] mxmd:flex-col mxmd:flex flex-1 page-content-wrapper">
    <div class="mxmd:pb-[3.33vh] pb-[30px] page-content-container">
        <h1 class="typog-title-g"><?php the_title(); ?></h1>

        <?php
        if ( ! empty($atl_vdo_embed) ) {
        ?>
        <div class="mt-[20px] video-wrapper"><?php echo $atl_vdo_embed; ?></div>
        <?php
        }
        ?>

        <div class="mxmd:mt-[30px] md:mt-[20px] content-tabs-wrapper">
            <ul id="tabs" class="mxmd:hidden link-tabs flex tabs gap-x-[2.92vw]">
                <li class="tab"><a href="#sobre"><?php esc_attr_e('Sobre','amrwp'); ?></a></li>
                <?php if ( ! empty($atl_als) ) { ?>
                <li class="tab"><a href="#aulas-selecionadas"><?php esc_attr_e('Aulas Selecionadas','amrwp'); ?></a></li>
                <?php } ?>
                <?php if ( ! empty($atl_mtrs) ) { ?>
                <li class="tab"><a href="#material-complementar"><?php esc_attr_e('Material Complementar','amrwp'); ?></a></li>
                <?php } ?>
            </ul>
            <ul class="mt-[20px] content-tabs">
                <li id="sobre">
                    <div>
                        <h2 class="md:hidden title"><button class="btn-reset-styles btn-toggle-content"><?php esc_attr_e('Sobre','amrwp'); ?></button></h2>
                        <div class="mxmd:text-[17px] content editor-content">
                            <?php the_content(); ?>
                        </div>
                    </div>
                </li>
                <?php if ( ! empty($atl_als) ) { ?>
                <li id="aulas-selecionadas">
                    <div class="md:mt-[10px]">
                        <h2 class="md:hidden title"><button class="btn-reset-styles btn-toggle-content"><?php esc_attr_e('Aulas Selecionadas','amrwp'); ?></button></h2>
                        <div class="content">
                            <ul class="w-full flex flex-col gap-y-[20px]">
                            <?php foreach ($atl_als as $aula) {
                            ?>
                                <li>
                                    <a class="resource-item-link" href="<?php echo get_permalink( $aula->ID ) ; ?>">
                                        <p class="resource-item-name items-center flex gap-x-[10px]"><img src="<?php echo public_url(); ?>images/icon-play.svg" width="15" height="15" alt=""> <?php esc_attr_e('Aula','amrwp'); ?></p>
                                        <h3 class="resource-item-title"><?php echo $aula->post_title; ?></h3>
                                    </a>
                                </li>
                            <?php
                            }
                            ?>
                            </ul>
                        </div>
                    </div>
                </li>
                <?php } ?>
                <?php if ( ! empty($atl_mtrs) ) { ?>
                <li id="material-complementar">
                    <div>
                        <h2 class="md:hidden title"><button class="btn-reset-styles btn-toggle-content"><?php esc_attr_e('Material Complementar','amrwp'); ?></button></h2>
                        <div class="flex flex-col gap-y-[20px] content">
                        <?php
                        foreach ($atl_mtrs as $material) {
                            if ( $material['atl_mtrs_lnk'] ) {
                                $aula_link = $material['atl_mtrs_lnk'];
                                if ( $aula_link['title'] && $aula_link['url'] ) {
                            ?>
                        <a class="[&:not(:first-child)]:mt-[16px] resource-item-link material-link-type-<?php if ( isset( $material['atl_mtrs_tp'] )  ) { echo $material['atl_mtrs_tp']; } ?>" <?php if ( $aula_link['target'] ) echo 'target="' . $aula_link['target'] . '"'; ?> href="<?php echo $aula_link['url']; ?>" class="link-material">
                                <p class="resource-item-name">
                                <?php
                                if ( isset( $material['atl_mtrs_tp'] ) ) {
                                    if ( 'video' == $material['atl_mtrs_tp'] ) echo __( 'Vídeo', 'amrwp' );
                                    if ( 'livro' == $material['atl_mtrs_tp'] ) echo __( 'Livro', 'amrwp' );
                                    if ( 'texto' == $material['atl_mtrs_tp'] ) echo __( 'Texto', 'amrwp' );
                                    if ( 'arquivo' == $material['atl_mtrs_tp'] ) echo __( 'Arquivo', 'amrwp' );
                                    if ( 'podcast' == $material['atl_mtrs_tp'] ) echo __( 'Podcast', 'amrwp' );
                                }
                                ?>
                                </p>
                                <h3 class="resource-item-title"><?php echo $aula_link['title']; ?></h3>
                                <?php if ( $material['atl_mtrs_txt'] ) { ?>
                                <p class="resource-item-desc"><?php echo $material['atl_mtrs_txt']; ?></p>
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
        </div>
        <!-- /.content-tabs-wrapper -->

    </div>
    <!-- /.page-content-container -->

</div>
<!-- /.page-content -->

<?php
endwhile; // while ( have_posts() ): the_post();
get_footer();
?>