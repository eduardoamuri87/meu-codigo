<?php
/**
 * Template name: LP Dinheiro sem medo
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

get_header();

?>

<?php
if ( have_posts() ): 
    while ( have_posts() ): the_post();
    ?>
    
    <?php
    // Campos de "Landing page - DSM: ajustes do cabeçalho" (includes/acf-campos-extras.php)
    $hdr_layout = ( function_exists("get_field") && get_field("lp_dsm_hdr_layout") ) ? get_field("lp_dsm_hdr_layout") : 'padrao';
    $hdr_classes = 'lp-dsm-header layout-' . $hdr_layout;
    if ( function_exists("get_field") && get_field("lp_dsm_hdr_sem_ilustra") ) $hdr_classes .= ' sem-ilustracao';

    // Frase + botão: na coluna da esquerda no layout padrão, na da direita no "logo-frase".
    $hdr_titulo_cta = function () { ?>
                <?php if ( function_exists("get_field") && get_field("lp_dsm_hdr_tit") ) { ?>
                <h1 class="page-title"><?php the_field("lp_dsm_hdr_tit"); ?></h1>
                <?php } ?>
                <a href="#matricula" class="btn-cta">Quero me matricular</a>
    <?php };
    ?>
    <header class="<?php echo esc_attr( $hdr_classes ); ?>">
        <div class="container">
            <div class="col-left">
                <img class="lp-dsm-logo" src="<?php echo public_url(); ?>images/lp-dsm/logo-dsm.svg" width="220" height="79" alt="Dinheiro sem medo">
                <?php if ( 'logo-frase' !== $hdr_layout ) $hdr_titulo_cta(); ?>
            </div>
            <!-- /.col-left -->
             <div class="col-right">
                <?php if ( 'logo-frase' === $hdr_layout ) { ?>
                    <?php $hdr_titulo_cta(); ?>
                <?php } elseif ( function_exists("get_field") && get_field("lp_dsm_hdr_vdo") ) { ?>
                <div class="video">
                    <?php echo get_field('lp_dsm_hdr_vdo'); ?>
                </div>
                <?php } elseif ( function_exists("get_field") && get_field("lp_dsm_hdr_img") ) { ?>
                <div class="foto">
                    <?php amrwp_img_tag_generate( get_field("lp_dsm_hdr_img"), 'large', '', false ); ?>
                </div>
                <?php } ?>
             </div>
        </div>
        <!-- /.container -->
    </header>
    <?php if ( function_exists("get_field") && get_field("intro_texto_01") ) { ?>
        <section class="lp-dsm-intro">
            <div class="container">
                <h2 class="lp-dsm-intro-title"><?php the_field("intro_texto_01"); ?></h2>
                <div class="lp-dsm-intro-texts">
                    <div class="col-left">
                    <?php if ( function_exists("get_field") && get_field("intro_bloco_txt_01") ) { ?>
                        <div class="mb-[10px]"><?php the_field("intro_bloco_txt_01"); ?></div>
                    <?php } ?>
                    <?php if ( function_exists("get_field") && get_field("intro_bloco_img_01") ) { ?>
                        <?php amrwp_img_tag_generate( get_field("intro_bloco_img_01") ); ?>
                    <?php } ?>
                    </div>
                    <div class="col-right">
                    <?php if ( function_exists("get_field") && get_field("intro_bloco_txt_02") ) { ?>
                        <div class="mxmd:mb-[20px] md:mb-[10px]"><?php the_field("intro_bloco_txt_02"); ?></div>
                    <?php } ?>
                    <?php if ( function_exists("get_field") && get_field("intro_bloco_img_02") ) { ?>
                        <div class="img-footer">
                            <?php amrwp_img_tag_generate( get_field("intro_bloco_img_02") ); ?>
                        </div>
                    <?php } ?>
                    </div>
                </div>
                <!-- /.lp-dsm-intro-texts -->
            </div>
            <!-- /.container -->
        </section>
    <?php } // if ( function_exists("get_field") && get_field("intro_texto_01") ) { ?>
    <?php if ( function_exists("get_field") && have_rows("motivos") ) { ?>
        <section class="lp-dsm-reasons">
            <div class="container">
                <?php if ( function_exists("get_field") && get_field("motivos_titulo") ) { ?>
                <h2 class="lp-dsm-reasons-title"><?php the_field("motivos_titulo"); ?></h2>
                <?php } ?>
                <div class="lp-dsm-reasons-list">
                    <?php
                    $motivos = get_field('motivos');
                    ?>
                    <div class="col-top">
                        <div class="col-top-left">
                            <?php
                            if ( isset($motivos[0]) ) {
                                $motivo_icone = '';
                                $motivo_titulo = '';
                                $motivo_titulo = '';
                                if ( isset( $motivos[0]['icone'] ) ) {
                                    $motivo_icone = $motivos[0]['icone'];
                                }
                                if ( isset( $motivos[0]['titulo'] ) ) {
                                    $motivo_titulo = $motivos[0]['titulo'];
                                }
                                if ( isset( $motivos[0]['texto'] ) ) {
                                    $motivo_texto = $motivos[0]['texto'];
                                }
                                include('includes/lp-dsm-reason-item.php');
                            }
                            ?>
                        </div>
                        <!-- /.col-top-left -->
                         <div class="col-top-right">
                            <div class="col-top-left-topcols">
                            <?php
                            if ( isset($motivos[1]) ) {
                                $motivo_icone = '';
                                $motivo_titulo = '';
                                $motivo_titulo = '';
                                if ( isset( $motivos[1]['icone'] ) ) {
                                    $motivo_icone = $motivos[1]['icone'];
                                }
                                if ( isset( $motivos[1]['titulo'] ) ) {
                                    $motivo_titulo = $motivos[1]['titulo'];
                                }
                                if ( isset( $motivos[1]['texto'] ) ) {
                                    $motivo_texto = $motivos[1]['texto'];
                                }
                                include('includes/lp-dsm-reason-item.php');
                            }
                            if ( isset($motivos[2]) ) {
                                $motivo_icone = '';
                                $motivo_titulo = '';
                                $motivo_titulo = '';
                                if ( isset( $motivos[2]['icone'] ) ) {
                                    $motivo_icone = $motivos[2]['icone'];
                                }
                                if ( isset( $motivos[2]['titulo'] ) ) {
                                    $motivo_titulo = $motivos[2]['titulo'];
                                }
                                if ( isset( $motivos[2]['texto'] ) ) {
                                    $motivo_texto = $motivos[2]['texto'];
                                }
                                include('includes/lp-dsm-reason-item.php');
                            }
                            ?>

                            </div>
                            <div class="col-top-left-bottomcol">
                                <?php
                                if ( isset($motivos[3]) ) {
                                    $motivo_icone = '';
                                    $motivo_titulo = '';
                                    $motivo_titulo = '';
                                    if ( isset( $motivos[3]['icone'] ) ) {
                                        $motivo_icone = $motivos[3]['icone'];
                                    }
                                    if ( isset( $motivos[3]['titulo'] ) ) {
                                        $motivo_titulo = $motivos[3]['titulo'];
                                    }
                                    if ( isset( $motivos[3]['texto'] ) ) {
                                        $motivo_texto = $motivos[3]['texto'];
                                    }
                                    include('includes/lp-dsm-reason-item.php');
                                }
                                ?>
                            </div>
                         </div>
                    </div>
                    <!-- /.col-top -->
                     <div class="col-bottom">
                     <?php
                        if ( isset($motivos[4]) ) {
                            $motivo_icone = '';
                            $motivo_titulo = '';
                            $motivo_titulo = '';
                            if ( isset( $motivos[4]['icone'] ) ) {
                                $motivo_icone = $motivos[4]['icone'];
                            }
                            if ( isset( $motivos[4]['titulo'] ) ) {
                                $motivo_titulo = $motivos[4]['titulo'];
                            }
                            if ( isset( $motivos[4]['texto'] ) ) {
                                $motivo_texto = $motivos[4]['texto'];
                            }
                            include('includes/lp-dsm-reason-item.php');
                        }
                        ?>
                        <?php
                        if ( isset($motivos[5]) ) {
                            $motivo_icone = '';
                            $motivo_titulo = '';
                            $motivo_titulo = '';
                            if ( isset( $motivos[5]['icone'] ) ) {
                                $motivo_icone = $motivos[5]['icone'];
                            }
                            if ( isset( $motivos[5]['titulo'] ) ) {
                                $motivo_titulo = $motivos[5]['titulo'];
                            }
                            if ( isset( $motivos[5]['texto'] ) ) {
                                $motivo_texto = $motivos[5]['texto'];
                            }
                            include('includes/lp-dsm-reason-item.php');
                        }
                        ?>
                     </div>
                     <!-- /.col-bottom -->
                </div>
                <!-- /.lp-dsm-reasons-list -->
            </div>
            <!-- /.container -->
        </section>
        <!-- /.lp-dsm-reasons -->
    <?php } // if ( function_exists("get_field") && have_rows("motivos") ) { ?>

    <?php if ( function_exists("get_field") && get_field("plantoes_-_titulo") || get_field("consultoria_-_titulo") ) { ?>
        <div class="lp-dsm-articles">
            <div class="container">
                <article class="lp-dsm-article-item lp-dsm-article-top">
                    <div class="col-left">
                        <?php if ( get_field("plantoes_-_titulo") ) { ?>
                        <h2 class="lp-dsm-article-title"><?php echo get_field("plantoes_-_titulo"); ?></h2>
                        <?php } ?>
                        <?php if ( get_field("plantoes_-_texto") ) { ?>
                        <div class="lp-dsm-article-text"><?php echo get_field("plantoes_-_texto"); ?></div>
                        <?php } ?>
                    </div>
                    <!-- /.col-left -->
                     <div class="col-right">
                     <?php if ( function_exists("get_field") && get_field("plantoes_-_imagem") ) { ?>
                        <?php amrwp_img_tag_generate( get_field("plantoes_-_imagem") ); ?>
                    <?php } ?>
                     </div>
                     <!-- /.col-right -->
                </article>
                <!-- /.article-top -->
                <article class="lp-dsm-article-item lp-dsm-article-bottom">
                    <div class="col-left">
                        <?php if ( get_field("consultoria_-_titulo") ) { ?>
                        <h2 class="lp-dsm-article-title"><?php echo get_field("consultoria_-_titulo"); ?></h2>
                        <?php } ?>
                        <?php if ( get_field("consultoria_-_texto") ) { ?>
                        <div class="lp-dsm-article-text"><?php echo get_field("consultoria_-_texto"); ?></div>
                        <?php } ?>
                    </div>
                    <!-- /.col-left -->
                     <div class="col-right">
                     <?php if ( function_exists("get_field") && get_field("consultoria_-_imagem") ) { ?>
                        <?php amrwp_img_tag_generate( get_field("consultoria_-_imagem") ); ?>
                    <?php } ?>
                     </div>
                     <!-- /.col-right -->
                </article>
                <!-- /.article-top -->
            </div>
            <!-- /.container -->

        </div>
    <?php } // if ( function_exists("get_field") && get_field("plantoes_-_titulo") || get_field("consultoria_-_titulo") ) { ?>
    <?php if ( function_exists("get_field") && get_field("acesso_titulo") ) { ?>
        <section class="lp-dsm-access">
            <div class="container">
                <div class="col-left">
                    <h2 class="lp-dsm-access-title"><?php the_field("acesso_titulo"); ?></h2>
                    <?php if ( get_field("acesso_texto") ) { ?>
                    <div class="lp-dsm-access-text">
                        <?php the_field("acesso_texto"); ?>
                    </div>
                    <?php } ?>
                </div>
                <div class="col-right">
                <?php if ( get_field("acesso_img") ) { ?>
                    <?php amrwp_img_tag_generate( get_field("acesso_img") ); ?>
                <?php } ?>
                </div>
            </div>
            <!-- /.container -->
        </section>
        <!-- /.lp-dsm-access -->
    <?php } // if ( function_exists("get_field") && get_field("acesso_titulo") ) { ?>
    <?php if ( function_exists("get_field") && 'lista' == get_field("lista_ou_matricula") && get_field("lista_titulo") ) { ?>
        <section id="matricula" class="lp-dsm-list-registration <?php the_field("lista_ou_matricula"); ?>">
            <div class="container">
                <div class="col-left">
                    <h2 class="lp-dsm-list-registration-title"><?php the_field("lista_titulo"); ?></h2>
                    <?php if ( get_field("lista_texto") ) { ?>
                    <div class="lp-dsm-list-registration-text">
                        <?php the_field("lista_texto"); ?>
                    </div>
                    <?php } ?>
                    <?php if ( get_field("lista_url") ) { $ilist_url = get_field("lista_url"); ?>
                    <?php if ( isset($ilist_url) && $ilist_url['title'] && $ilist_url['url'] ) { ?>
                    <div class="lp-dsm-list-registration-btn">
                        <a class="lp-dsm-list-registration-link" <?php if ( $ilist_url['target'] ) echo 'target="' . $ilist_url['target'] . '"'; ?> href="<?php echo $ilist_url['url']; ?>">
                            <?php echo $ilist_url['title']; ?>
                        </a>
                    </div>
                    <?php } // if ( isset($ilist_url) ) { ?>
                    <?php } ?>
                </div>
                <div class="col-right">
                <?php if ( get_field("lista_imagem") ) { ?>
                    <?php amrwp_img_tag_generate( get_field("lista_imagem") ); ?>
                <?php } ?>
                </div>
            </div>
        </section>
        <!-- /.lp-dsm-list-registration -->
    <?php } // if ( function_exists("get_field") && get_field("lista_ou_matricula") && get_field("lista_mat_titulo") ) { ?>
    <?php if ( function_exists("get_field") && 'matricula' == get_field("lista_ou_matricula") && get_field("mat_titulo") ) { ?>
        <section id="matricula" class="lp-dsm-list-registration <?php the_field("lista_ou_matricula"); ?>">
            <div class="container">
                <div class="col-left">
                    <h2 class="lp-dsm-list-registration-title"><?php the_field("mat_titulo"); ?></h2>
                    <?php if ( get_field("mat_texto") ) { ?>
                    <div class="lp-dsm-list-registration-text">
                        <?php the_field("mat_texto"); ?>
                    </div>
                    <?php } ?>
                    <?php if ( get_field("mat_url") ) { $ilist_url = get_field("mat_url"); ?>
                    <?php if ( isset($ilist_url) && $ilist_url['title'] && $ilist_url['url'] ) { ?>
                    <div class="lp-dsm-list-registration-btn">
                        <a class="lp-dsm-list-registration-link" <?php if ( $ilist_url['target'] ) echo 'target="' . $ilist_url['target'] . '"'; ?> href="<?php echo $ilist_url['url']; ?>">
                            <?php echo $ilist_url['title']; ?>
                        </a>
                    </div>
                    <?php } // if ( isset($ilist_url) ) { ?>
                    <?php } ?>
                </div>
                <div class="col-right">
                <?php if ( get_field("mat_imagem") ) { ?>
                    <?php amrwp_img_tag_generate( get_field("mat_imagem") ); ?>
                <?php } ?>
                </div>
            </div>
        </section>
        <!-- /.lp-dsm-list-registration -->
    <?php } // if ( function_exists("get_field") && get_field("lista_ou_matricula") && get_field("lista_mat_titulo") ) { ?>
    <?php if ( function_exists("get_field") && have_rows("depoimts") ) { ?>
        <section class="lp-dsm-testimonials">
            <div class="container">
                <h2 class="lp-dsm-testimonials-title"><?php esc_attr_e('Depoimentos dos alunos','amrwp'); ?></h2>
                <div class="lp-dsm-testimonials-list">
                    <?php
                    while ( have_rows("depoimts") ): the_row();
                        ?>
                        <article class="lp-dsm-testimonials-item <?php if ( ! get_sub_field("depoim_foto") ) { ?>no-photo<?php } ?>">
                        <?php if ( get_sub_field("depoim_foto") ) { ?>
                            <figure class="col-photo">
                            <?php amrwp_img_tag_generate( get_sub_field("depoim_foto") ); ?>
                            </figure>
                        <?php } ?>
                        <div class="col-text">
                            <?php if ( get_sub_field('depoim_tit') ) { ?>
                            <p class="lp-dsm-testimonial-tit"><?php the_sub_field('depoim_tit'); ?></p>
                            <?php } ?>
                            <?php if ( get_sub_field('depoim_txt') ) { ?>
                            <div class="lp-dsm-testimonial-text"><?php the_sub_field('depoim_txt'); ?></div>
                            <?php } ?>
                            <?php if ( get_sub_field('depoim_nm') ) { ?>
                            <h3 class="lp-dsm-testimonial-name"><?php the_sub_field('depoim_nm'); ?></h3>
                            <?php } ?>
                        </div>
                        </article>
                        <?php
                    endwhile;
                    ?>
                </div>
                <!-- /.lp-dsm-testimonials-list -->
                <button class="lp-dsm-testimonials-list-arrow arrow-prev"></button><button class="lp-dsm-testimonials-list-arrow arrow-next"></button>
            </div>
            <!-- /.container -->
        </section>
        <!-- /.lp-dsm-testimonials -->
    <?php } // if ( function_exists("get_field") && have_rows("depoimts") ) { ?>
    <?php if ( function_exists("get_field") && have_rows("faq_bloco") ) { ?>
        <section class="lp-dsm-faq">
            <div class="container">
                <?php if ( get_field('faq_titulo') ) { ?>
                <h2 class="lp-dsm-faq-title"><?php the_field('faq_titulo'); ?></h2>
                <?php } ?>

                <div class="lp-dsm-faq-list">
                    <?php
                    while ( have_rows("faq_bloco") ): the_row();
                    ?>
                    <section class="lp-dsm-faq-block">
                    <?php if ( get_sub_field('faq_blc_tit') ) { ?>
                        <h3 class="lp-dsm-faq-subtitle"><?php the_sub_field('faq_blc_tit'); ?></h3>
                    <?php } ?>
                    <?php
                    $faq = array(); if ( get_sub_field('faq') ) { $faq = get_sub_field('faq');
                        foreach ($faq as $faq_items) {
                            if ( isset($faq_items['faq_perg']) && isset($faq_items['faq_resp']) ) {
                    ?>
                        <article class="lp-faq-item lp-dsm-faq-item">
                            <h4 class="lp-dsm-faq-item-title">
                                <button class="lp-faq-item-title-btn lp-dsm-faq-item-title-btn"><?php echo $faq_items['faq_perg']; ?></button>
                            </h4>
                            <div class="lp-faq-item-text lp-dsm-faq-item-text"><?php echo $faq_items['faq_resp']; ?></div>
                        </article>
                        <!-- /.lp-dsm-faq-item -->
                    <?php
                            } // if ( isset($faq_items['faq_perg']) && isset($faq_items['faq_resp']) ) {
                        }
                    }
                    ?>
                    </section>
                    <!-- /.lp-dsm-faq-block -->
                    <?php
                    endwhile;
                    ?>
                </div>
                <!-- /.lp-dsm-faq-list -->
            </div>
            <!-- /.container -->
        </section>
        <!-- /.lp-dsm-faq -->
    <?php } // if ( function_exists("get_field") && have_rows("faq_bloco") ) { ?>
    <?php if ( function_exists("get_field") && get_field("fale_txt") ) { ?>
        <section class="lp-dsm-contact">
            <div class="container">
                <?php if ( get_field('fale_tit') ) { ?>
                    <h2 class="lp-dsm-contact-title"><?php the_field('fale_tit'); ?></h2>
                <?php } ?>
                <?php if ( get_field('fale_txt') ) { ?>
                    <div class="lp-dsm-contact-text"><?php the_field('fale_txt'); ?></div>
                <?php } ?>
                <img src="<?php echo public_url(); ?>images/lp-dsm/lp-dsm_amuri-logo.svg" width="120" height="30" alt="">
            </div>
            <!-- /.container -->
        </section>
        <!-- /.lp-dsm-contact -->
    <?php } // if ( function_exists("get_field") && get_field("fale_txt") ) { ?>
    <?php
    endwhile;
endif;
?>


<?php get_footer(); ?>