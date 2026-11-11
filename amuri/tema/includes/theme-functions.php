<?php
/**
 * Funções do tema
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

// PEGA O LINK DA PAGINA PELO SLUG
if ( ! function_exists( 'amrwp_get_page_link_by_slug' ) ):

function amrwp_get_page_link_by_slug($page_slug) {
  $page = get_page_by_path($page_slug);
  if ($page) :
    return get_permalink( $page->ID );
  else :
    return "#";
  endif;
}

endif; // if ( ! function_exists( 'amrwp_get_page_link_by_slug' ) ) {

// Pega o ID usando WPML
if ( ! function_exists( 'amrwp_theme_get_id_wpml' ) ):

function amrwp_theme_get_id_wpml( $idnumber, $element_type = 'page' ) {

    // Initialize the permalink value
    if ( ! isset($idnumber) ) return false;
    
    $newid = $idnumber;
    
    if ( function_exists('icl_object_id') ) {
        $newid = apply_filters( 'wpml_object_id', $idnumber, $element_type, TRUE );
    }

    return $newid;
}

endif; // if ( ! function_exists( 'amrwp_theme_get_id_wpml' ) ) {

// Pega o permalink pelo titulo - usando WPML
// http://tommcfarlin.com/get-permalink-by-slug/
if ( ! function_exists( 'amrwp_theme_get_permalink_by_title' ) ):

function amrwp_theme_get_permalink_by_title( $title ) {

    // Initialize the permalink value
    $permalink = null;

    // Try to get the page by the incoming title
    $page = get_page_by_title( strtolower( $title ) );
    if ( function_exists('icl_object_id') ) {
        $page = icl_object_id( $page->ID, 'page', FALSE, ICL_LANGUAGE_CODE );
    }

    // If the page exists, then let's get its permalink
    if( null != $page ) {
        $permalink = get_permalink( $page );
    } // end if

    return $permalink;

}

endif; // if ( ! function_exists( 'amrwp_theme_get_permalink_by_title' ) ) {

// Pega o permalink pelo titulo - usando WPML
// http://tommcfarlin.com/get-permalink-by-slug/
if ( ! function_exists( 'amrwp_theme_get_permalink_by_title_print' ) ):

function amrwp_theme_get_permalink_by_title_print( $title ) {

    // Initialize the permalink value
    $permalink = null;

    // Try to get the page by the incoming title
    $page = get_page_by_title( strtolower( $title ) );

    // If the page exists, then let's get its permalink
    if ( null != $page ) {
        $permalink = icl_link_to_element( $page->ID, 'page' , __( $title ) );
    } // end if
}
endif; // if ( ! function_exists( 'amrwp_theme_get_permalink_by_title_print' ) ) {

if ( ! function_exists( 'amrwp_paging_nav' ) ):
function amrwp_paging_nav( $totalPages = '', $pageNumber ) {

    if ( $totalPages != '' ) {
        $postsMaxNumPage = $totalPages;
    } else {
        $postsMaxNumPage = $GLOBALS['wp_query']->max_num_pages;
    }

    // Don't print empty markup if there's only one page.
    if ( $postsMaxNumPage < 2 ) {
        return;
    }

    $bigNumber = 999999999;

    if ( get_query_var('paged') ) {
        $pageNumber = get_query_var('paged');
    }

    ?>

    <nav class="pagination-wrapper">
        
        <div class="pagination">

    <?php
        echo paginate_links( array(
            'base' => str_replace( $bigNumber, '%#%', esc_url( get_pagenum_link( $bigNumber ) ) ),
            'format' => '?paged=%#%',
            'current' => max( 1, $pageNumber ),
            'total' => $postsMaxNumPage,
            'prev_text'    => __('&lt;'),
            'next_text'    => __('mostrar +')
          ) );

    ?>

        </div>

    </nav> <!-- .pagination-wrapper container -->
    <?php

} // amrwp_paging_nav()
endif; // if ( ! function_exists( 'amrwp_paging_nav' ) ):

if ( ! function_exists( 'amrwp_img_tag_generate' ) ):

function amrwp_img_tag_generate( $img, $size = 'full', $imgClass = '', $lazyLoad = true, $style = '', $attr = '' ) {

    if ( ! isset($img) || '' == $img ) return false;

    if ( strpos( $img['mime_type'], 'gif' ) > -1 ) {
    ?>
        <img <?php if ( $lazyLoad ) { ?>loading="lazy"<?php } ?> src="<?php echo $img['url'] ?>" alt="<?php echo $img['alt'] ?>" width="<?php echo $img['width'] ?>" height="<?php echo $img['height'] ?>" class="<?php echo $imgClass ?>" style="<?php echo $style; ?>">
    <?php
    } else {
        if ( $lazyLoad ) {
            echo wp_get_attachment_image( $img['ID'], $size, '', array( 'class' => $imgClass, 'loading' => 'lazy', 'style' => $style, $attr => '' ) );
        } else {
            echo wp_get_attachment_image( $img['ID'], $size, '', array( 'class' => $imgClass, 'loading' => 'eager', 'style' => $style, $attr => '' ) );
        }
    }
}

endif; // if ( ! function_exists( 'amrwp_img_tag_generate' ) ) {

if ( ! function_exists('amrwp_can_user_access_content') ):
function amrwp_can_user_access_content($post_id = '',$user_id = ''){
    
    if ( ! is_user_logged_in() ) return false;

    if ( '' == $user_id ) {
        $user_id = get_current_user_id();
    }
    
    if ( get_post_meta($post_id,'_wc_memberships_force_public',true) == 'yes' ) return true;

    $args = array( 'status' => array( 'active' ));
    $plans = wc_memberships_get_user_memberships( $user_id, $args );
    $user_plans = array();
    foreach ( $plans as $plan ) {
        array_push($user_plans,$plan->plan_id);
    }
    $rules = wc_memberships()->get_rules_instance()->get_post_content_restriction_rules( $post_id );

    foreach ( $rules as $rule ) {
        if( in_array($rule->get_membership_plan_id(), $user_plans) ) {
            return true;
        }
    }       
    return false;
}
endif; // if ( ! function_exists('amrwp_can_user_access_content') ):

if ( ! function_exists('amrwp_get_user_name') ):
function amrwp_get_user_name( $user_id = null ) {
 
    $user_info = $user_id ? new WP_User( $user_id ) : wp_get_current_user();
    
    if ( $user_info->first_name ) { return $user_info->first_name; }
    
    return $user_info->display_name;
}
endif; //  // if ( ! function_exists('amrwp_get_users_name') ):

if ( ! function_exists('amrwp_get_users_first_last_name') ):
function amrwp_get_users_first_last_name( $user_id = null ) {

    $user_info = $user_id ? new WP_User( $user_id ) : wp_get_current_user();
    
    if ( $user_info->first_name ) {
    
        if ( $user_info->last_name ) {
        return $user_info->first_name . ' ' . $user_info->last_name;
        }
    
        return $user_info->first_name;
    }
    
    return $user_info->display_name;
    }
endif; // if ( ! function_exists('amrwp_get_users_first_last_name') ):

if ( ! function_exists('amrpw_get_program_course_id') ):
    function amrpw_get_program_course_id() {
        global $post;
        $post_id = $post->ID;
        $course_ID = false;

        if ( 'course' == get_post_type( $post_id ) ) {
            $course_ID = $post_id;
        }

        if ( 'lesson' == get_post_type( $post_id ) ) {
            $course_ID = get_post_meta( $post_id, '_lesson_course', true );
        }

        if ( 'amr_atalho' == get_post_type( $post_id ) || 'amr_plantao' == get_post_type( $post_id ) ) {
            $post_terms = wp_get_post_terms( $post_id, 'amr_atalho_programa' );
            
            if ( ! empty($post_terms) ) {
                $post_term_id = $post_terms[0]->term_id;
                if ( function_exists('get_field') && get_field('pgm_crs_rlcd', 'amr_atalho_programa_' . $post_term_id) ) {
                    $course_ID = get_field('pgm_crs_rlcd', 'amr_atalho_programa_' . $post_term_id);
                }
            }
            
        }

        if ( 'page' == get_post_type( $post_id ) ) {

            if ( ! is_page_template('page-painel-programa.php') ) {
                $post_id = $post->post_parent;
            }

            if ( function_exists('get_field') && get_field('pgm_crs_rlcd', $post_id) ) {
                $course_ID = get_field('pgm_crs_rlcd', $post_id);
            }

        }

        return $course_ID;
    }
endif; // if ( ! function_exists('amrpw_get_program_course_id') ):

// Ajax functions
add_action("wp_ajax_amrwp_form_profile_address", "amrwp_form_profile_address");
add_action("wp_ajax_nopriv_amrwp_form_profile_address", "amrwp_form_profile_address");
if ( ! function_exists('amrwp_form_profile_address') ):
function amrwp_form_profile_address() {
    $error_msg = __('Ocorreu um erro: não foi possível atualizar seu endereço, verifique se digitou as informações corretamente ou tente novamente mais tarde.', 'amrwp');
    $error_fields = array();
    
    if ( !wp_verify_nonce( $_POST['formnonce'] , "amrwp_form_profile_address_nonce" ) || ! is_user_logged_in() || ! get_current_user_id() ) {
        exit("Erropadrao-" . $error_msg);
    }

    $user_id = get_current_user_id();

    if ( ! isset($_POST['entregacep']) || empty(esc_attr($_POST['entregacep'])) || strlen(esc_attr($_POST['entregacep'])) != 9 ) {
        $error_fields[] = 'cep';
    }
    if ( ! isset($_POST['entregalogradouro']) || empty(esc_attr($_POST['entregalogradouro'])) ) {
        $error_fields[] = 'logradouro';
    }
    if ( ! isset($_POST['entregacidade']) || empty(esc_attr($_POST['entregacidade'])) ) {
        $error_fields[] = 'cidade';
    }
    if ( ! isset($_POST['entregaestado']) || empty(esc_attr($_POST['entregaestado'])) ) {
        $error_fields[] = 'estado';
    }
    if ( ! isset($_POST['entregapais']) || empty(esc_attr($_POST['entregapais'])) || strlen(esc_attr($_POST['entregapais'])) != 2 ) {
        $error_fields[] = 'pais';
    }

    $cep = $_POST['entregacep'];
    $cep_get = wp_remote_get( "https://viacep.com.br/ws/" . str_replace('-','',$cep) . "/json/" );
    if ( isset( $cep_get['response'] ) && isset( $cep_get['response']['code'] ) == 200 && isset( $cep_get['body'] ) ) {
        $cep_found = json_decode($cep_get['body']);
        if ( isset( $cep_found->erro ) && $cep_found->erro ) {
            $error_fields[] = 'cep';
        }
    }

    if ( ! empty($error_fields) && count($error_fields) > 0 ) {
        exit("Errofields-" . implode('-',$error_fields));
    }

    $user_customer = new WC_Customer( $user_id );
    $user_customer->set_billing_country( esc_attr( $_POST['entregapais'] ) );
    $user_customer->set_billing_postcode( esc_attr( $_POST['entregacep'] ) );
    $user_customer->set_billing_city( esc_attr( $_POST['entregacidade'] ) );
    $user_customer->set_billing_state( esc_attr( $_POST['entregaestado'] ) );
    $user_customer->set_billing_address_1( esc_attr( $_POST['entregalogradouro'] ) );
    if ( isset($_POST['entregacomplemento']) && ! empty(esc_attr($_POST['entregacomplemento'])) ) {
        $user_customer->set_billing_address_2( esc_attr( $_POST['entregacomplemento'] ) );
    }
    if ( isset($_POST['entreganumero']) && ! empty(esc_attr($_POST['entreganumero'])) ) {
        if ( get_user_meta( $user_id, 'billing_number', true ) ) {
            update_user_meta( $user_id, 'billing_number', esc_attr( $_POST['entreganumero'] ) );
        } else {
            add_user_meta( $user_id, 'billing_number', esc_attr( $_POST['entreganumero'] ), true );
        }

    }
    $address_set = $user_customer->save();
    if ( $address_set ) {
        exit('Sucesso-');
    } else {
        exit('Erro-' . $error_msg);
    }

}
endif; // if ( ! function_exists('amrwp_form_profile_address') ):

add_action("wp_ajax_amrwp_form_profile_image", "amrwp_form_profile_image");
add_action("wp_ajax_nopriv_amrwp_form_profile_image", "amrwp_form_profile_image");
if ( ! function_exists('amrwp_form_profile_image') ):
function amrwp_form_profile_image() {
    $amr_plataforma_avatars = wp_upload_dir();
    $amr_plataforma_avatars_url = $amr_plataforma_avatars['baseurl'];
    $amr_plataforma_avatars_url .= '/amr-plataforma-avatars/';
    $amr_plataforma_avatars = $amr_plataforma_avatars['basedir'];
    $amr_plataforma_avatars .= '/amr-plataforma-avatars/';
    $error_msg = __('Ocorreu um erro: não foi possível salvar sua imagem, verifique se enviou a imagem corretamente, envie outra imagem maior ou tente novamente mais tarde.', 'amrwp');
    $error_msg_type_size = __('Ocorreu um erro: ou tamanho do arquivo enviado é maior que o limite permitido (16 megabytes) ou não é um dos formatos permitidos (JPEG, JPG ou PNG). Selecione outra imagem e tente novamente.', 'amrwp');
    $error_msg_dimensao = __('Ocorreu um erro: ou a imagem enviada é muito pequena ou está em um formato não suportado. Tente enviar outra imagem.', 'amrwp');

    if ( ! isset($_POST['formnonce']) ||  !wp_verify_nonce( $_POST['formnonce'] , "amrwp_form_profile_image_nonce" ) || ! is_user_logged_in() || ! get_current_user_id() || ! isset( $_FILES['perfilimagem'] ) ) {
        exit("Erro-" . $error_msg);
    }
    
    if (isset($_FILES["perfilimagem"]["type"])) {
        $validextensions = array("jpeg", "jpg", "png");
        $temporary = explode(".", $_FILES["perfilimagem"]["name"]);
        $file_extension = end($temporary);
        if ((($_FILES["perfilimagem"]["type"] == "image/png") || ($_FILES["perfilimagem"]["type"] == "image/jpg") || ($_FILES["perfilimagem"]["type"] == "image/jpeg")
        ) && ($_FILES["perfilimagem"]["size"] < 16000000)
             && in_array(strtolower($file_extension), $validextensions)) {
            if ($_FILES["perfilimagem"]["error"] > 0) {
                exit("Erro-" . $error_msg);
            } else {
                $filename = rand((int)1000000000000000000000000,(int)9999999999999999999999999) . '_' . $_FILES["perfilimagem"]["name"];
                if (file_exists($amr_plataforma_avatars . $filename)) {
                    exit("Erro-" . $error_msg);
                } else {
                    $sourcePath = $_FILES['perfilimagem']['tmp_name'];
                    $targetPath = $amr_plataforma_avatars . $filename;
                    $move_file = move_uploaded_file($sourcePath, $targetPath);
                    
                    if ( $move_file ) {

                        $editor_img = wp_get_image_editor($targetPath, array());
                        $editor_img_result = $editor_img->resize(300, 300, true);

                        if(!is_wp_error($editor_img_result)) {
                            $amr_plataforma_avatars_url .= $filename;
                            $filename = $editor_img->save($targetPath);
                            $user_id = get_current_user_id();
                            if ( get_user_meta( $user_id, 'amr_user_profile_img', true ) ) {
                                update_user_meta( $user_id, 'amr_user_profile_img', $amr_plataforma_avatars_url );
                            } else {
                                add_user_meta( $user_id, 'amr_user_profile_img', $amr_plataforma_avatars_url, true );
                            }
                            echo 'Sucesso-' . $amr_plataforma_avatars_url;
                            die();
                        } else {
                            exit('Erro-' . $error_msg_dimensao);
                        }
    
                    } else {
                        exit('Erro-' . $error_msg);
                    }
                }
            }
        } else {
            exit("Erro-" . $error_msg_type_size);
        }
    }

}
endif; // if ( ! function_exists('amrwp_form_profile_image') ):

add_action("wp_ajax_amrwp_form_profile_edit", "amrwp_form_profile_edit");
add_action("wp_ajax_nopriv_amrwp_form_profile_edit", "amrwp_form_profile_edit");
if ( ! function_exists('amrwp_form_profile_edit') ):
function amrwp_form_profile_edit() {
    $error_msg = __('Ocorreu um erro: não foi possível editar seu perfil, verifique se digitou as informações corretamente ou tente novamente mais tarde.', 'amrwp');
    
    if ( !wp_verify_nonce( $_POST['nonce'] , "amrwp_form_profile_edit_nonce" ) || ! is_user_logged_in() || ! get_current_user_id() || ! isset( $_POST['form_field_name'] ) || empty( $_POST['form_field_name'] ) || ! isset( $_POST['form_field_value'] ) || empty( $_POST['form_field_value'] ) ) {
        exit("Erro-" . $error_msg);
    }
    
    $current_user_id = get_current_user_id();

    if ( 'perfilnome' == $_POST['form_field_name'] || 'perfilsobrenome' == $_POST['form_field_name'] ) {

        if ( 'perfilnome' == $_POST['form_field_name'] ) {

            $update_user = wp_update_user(array(
                'ID' => $current_user_id,
                'first_name' => esc_attr( $_POST['form_field_value'] )
            ));
        }

        if ( 'perfilsobrenome' == $_POST['form_field_name'] ) {
            $update_user = wp_update_user(array(
                'ID' => $current_user_id,
                'last_name' => esc_attr( $_POST['form_field_value'] )
            ));
        }

        if ( $update_user ) {
            exit( amrwp_get_users_first_last_name() );
        } else {
            exit("Erro-" . $error_msg);
        }
    }

    if ( 'perfilemail' == $_POST['form_field_name'] ) {

        if (!is_email(esc_attr( $_POST['form_field_value'] ))) {
            $error_msg = __('O e-mail digitado não é válido, tente novamente.', 'amrwp');
            exit("Erro-" . $error_msg);
        }
        elseif(email_exists(esc_attr( $_POST['form_field_value'] )) != $current_user->ID ) {
            $error_msg = __('O e-mail digitado está em uso por outro usuário, tente um endereço diferente.', 'amrwp');
            exit("Erro-" . $error_msg);
        }
        else{
            $update_user = wp_update_user( array (
                'ID' => $current_user_id,
                'user_email' => esc_attr( $_POST['form_field_value'] )
            ));

            if ( $update_user ) {
                exit("Sucesso-E-mail atualizado com sucesso!");
            }
        }

    }

    if ( 'perfilsenha' == $_POST['form_field_name'] ) {

        $update_user = wp_update_user( array (
            'ID' => $current_user_id,
            'user_pass' => esc_attr( $_POST['form_field_value'] )
        ));

        if ( $update_user ) {
            exit("Sucesso-Senha atualizada com sucesso!");
        }

    }
    
}
endif; // if ( ! function_exists('amrwp_form_profile_edit') ):


add_action("wp_ajax_amrwp_load_plantoes", "amrwp_load_plantoes");
add_action("wp_ajax_nopriv_amrwp_load_plantoes", "amrwp_load_plantoes");

if ( ! function_exists('amrwp_load_plantoes') ):
function amrwp_load_plantoes() {

    if ( !wp_verify_nonce( $_POST['nonce'] , "amrwp_load_plantoes" ) || ! filter_var( intval( $_POST['pagenum'] ), FILTER_VALIDATE_INT ) || ! isset ($_POST['term_programa']) ) {
        exit("Erro");
    }

    $loopPageNum = $_POST['pagenum'];

    if ( isset( $_POST['term_assunto'] ) && '' != $_POST['term_assunto'] && ! empty($_POST['term_assunto']) ) {
        $tax_query = array(
            'relation' => 'AND',
            array(
                'taxonomy' => 'amr_atalho_programa',
                'field' => 'term_id',
                'terms' => $_POST['term_programa']
            ),
            array(
                'taxonomy' => 'amr_plantao_assunto',
                'field' => 'slug',
                'terms' => $_POST['term_assunto']
            ));
    } else {
        $tax_query = array(
            array(
                'taxonomy' => 'amr_atalho_programa',
                'field' => 'term_id',
                'terms' => $_POST['term_programa']
            ));
    }

    if ( isset($_POST['plantaoFrom']) && isset($_POST['plantaoTo']) ) {
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

    $plnt_post_type = 'amr_plantao';
    if ( isset($_REQUEST['post_type']) ) {
        $plnt_post_type = $_REQUEST['post_type'];
    }

    $plantoes_ListaArgs = array( 
        'post_type' => $plnt_post_type,
        'posts_per_page' => 12,
        'paged' => $loopPageNum,
        'order' => 'DESC',
        'orderby' => 'DATE',
        'tax_query' => $tax_query
    );
    if ( isset( $date_query ) ) {
        $plantoes_ListaArgs['date_query'] = $date_query;
    }
    $plantoes_ListaLoop = new WP_Query( $plantoes_ListaArgs );

    if ( $plantoes_ListaLoop->have_posts() ) {
        $loopMaxPages = $plantoes_ListaLoop->max_num_pages;

        while ( $plantoes_ListaLoop->have_posts() ) : $plantoes_ListaLoop->the_post();
            include( dirname(__FILE__) . '/../template-parts/plantao-post.php' );
        endwhile; // ( $plantoes_ListaLoop->have_posts() ) : $plantoes_ListaLoop->the_post();
        ?>
        <div class="plantoes-pagination-wrapper">
        <?php amrwp_paging_nav( $loopMaxPages, $loopPageNum ); ?>
        </div>
        <?php
        wp_reset_postdata();

    } // if ( $plantoes_ListaLoop->have_posts() ) {

    exit;

}
endif; // if ( ! function_exists('amrwp_load_plantoes') ):

add_filter('terms_clauses', 'amrwp_filter_terms_by_custm_post_type', 10, 3 );

if ( ! function_exists('amrwp_filter_terms_by_custm_post_type') ):
function amrwp_filter_terms_by_custm_post_type($clauses, $taxonomy, $args) {
    global $wpdb;

    $post_type = $args['amr_custom_post_type'] ?? '';

    // Proceed only if your custom parameter is set.
    if (empty($post_type)) {
        return $clauses;
    }

    // Modify the query to only include terms that have posts in the specified post type.
    $clauses['join'] .= " LEFT JOIN {$wpdb->term_relationships} AS tr ON tt.term_taxonomy_id = tr.term_taxonomy_id LEFT JOIN {$wpdb->posts} AS p ON tr.object_id = p.ID AND p.post_type = '{$post_type}'";
    $clauses['where'] .= " GROUP BY t.term_id HAVING COUNT(DISTINCT p.ID) > 0";

    return $clauses;
}

add_filter( 'woocommerce_pay_order_button_text', function() {
    return __( 'Quero realizar minha matrícula! :)', 'amrwp' );
} );

if ( ! function_exists( 'amrwp_plataforma_url' ) ) {
    function amrwp_plataforma_url( $path = '' ) {
        $base = defined( 'AMRWP_PLATAFORMA_URL' ) ? AMRWP_PLATAFORMA_URL : 'https://programas.amuri.com.br';
        return rtrim( $base, '/' ) . '/' . ltrim( $path, '/' );
    }
}

endif; // if ( ! function_exists('amrwp_filter_terms_by_custm_post_type') ):