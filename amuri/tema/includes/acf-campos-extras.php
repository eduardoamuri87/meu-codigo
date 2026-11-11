<?php
/**
 * Campos ACF registrados pelo código do tema.
 *
 * Os grupos de campos do site ficam no banco (criados pelo painel do ACF). Campos novos
 * entram aqui, em grupos próprios, para irem a produção junto com o tema sem precisar
 * recriá-los à mão no ACF.
 *
 * Atenção: não registrar campo local com "parent" apontando para um grupo do banco.
 * Quando existe campo local para um grupo, o ACF passa a listar só os campos locais e os
 * campos do banco somem do editor.
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 */

add_action( 'acf/init', function () {

    if ( ! function_exists( 'acf_add_local_field_group' ) ) return;

    // Ajustes do cabeçalho das LPs DSM, usados nas variações (ex.: /dinheirosemmedo-pf/).
    acf_add_local_field_group( array(
        'key'      => 'group_lp_dsm_hdr_foto',
        'title'    => 'Landing page - DSM: ajustes do cabeçalho',
        'fields'   => array(
            array(
                'key'           => 'field_lp_dsm_hdr_layout',
                'name'          => 'lp_dsm_hdr_layout',
                'label'         => 'Layout do cabeçalho',
                'type'          => 'radio',
                'choices'       => array(
                    'padrao'     => 'Vídeo à direita (padrão)',
                    'logo-frase' => 'Logo à esquerda, frase à direita (sem vídeo/foto)',
                ),
                'default_value' => 'padrao',
                'layout'        => 'vertical',
                'return_format' => 'value',
            ),
            array(
                'key'           => 'field_lp_dsm_hdr_sem_ilustra',
                'name'          => 'lp_dsm_hdr_sem_ilustra',
                'label'         => 'Esconder ilustração do canto',
                'instructions'  => 'Tira os quadradinhos ilustrados do canto superior direito do cabeçalho (só aparecem no desktop).',
                'type'          => 'true_false',
                'ui'            => 1,
                'default_value' => 0,
            ),
            // Só aparece no site se o campo de vídeo ("Landing page - DSM" > Cabeçalho) estiver vazio.
            array(
                'key'           => 'field_lp_dsm_hdr_img',
                'name'          => 'lp_dsm_hdr_img',
                'label'         => 'Foto (no lugar do vídeo)',
                'instructions'  => 'Aparece só quando o campo "Vídeo - código de incorporação" estiver vazio. Recorte automático na mesma proporção do vídeo.',
                'type'          => 'image',
                'return_format' => 'array',
                'preview_size'  => 'medium',
                'library'       => 'all',
            ),
        ),
        'location' => array(
            array(
                array( 'param' => 'page_template', 'operator' => '==', 'value' => 'page-lp-dsm.php' ),
            ),
        ),
        'menu_order' => 0,
        'position'   => 'acf_after_title',
        'style'      => 'default',
    ) );

} );
