<?php
/**
 * Template name: Editar perfil
 * Página para Editar perfil
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */
if ( ! is_user_logged_in() ) wp_redirect( get_bloginfo('home') );

include_once( 'includes/user-can-access.php' );

global $post;
$pageID = $post->ID;

get_header('curso');

if ( function_exists('get_field') ) {

    if ( get_field('prfl_tit', $pageID) ) {
        $prfl_tit = get_field('prfl_tit', $pageID);
    }
    if ( get_field('prfl_txt', $pageID) ) {
        $prfl_txt = get_field('prfl_txt', $pageID);
    }
    if ( get_field('prfl_img', $pageID) ) {
        $prfl_img = get_field('prfl_img', $pageID);
    }

}

$user_info = wp_get_current_user();
if ( $user_info->first_name ) { $user_first_name = $user_info->first_name; }
if ( $user_info->last_name ) { $user_last_name = $user_info->last_name; }
if ( $user_info->user_email ) { $user_email = $user_info->user_email; }

?>

<section class="mt-[40px] px-[3.29vw] relative max-w-[1130px] section-perfil-form">
    <div class="md:bg-[#95b2a8] relative text-blue-dark pt-[50px] pb-[20px] md:pb-[40px] pl-[2.19vw] mxlg:pr-[2.19vw] lg:pr-[21.96vw] max-w-[670px] box-title-image">
        <?php if ( isset($prfl_tit) ) { ?>
        <h1 class="leading-[1em] typog-title"><?php echo $prfl_tit; ?></h1>
        <?php } ?>
        <?php if ( isset($prfl_txt) ) { ?>
        <p class="mt-[15px] typog-body-small"><?php echo $prfl_txt; ?></p>
        <?php } ?>
        <?php if ( isset($prfl_img) ) { ?>
            <?php amrwp_img_tag_generate($prfl_img, 'full', 'mxlg:hidden w-[20.13vw] h-auto absolute bottom-0 right-[5px] max-w-[260px]', false); ?>
        <?php } ?>
    </div>

    <section class="md:mt-[40px]">
        <a name="editar-perfil" class="absolute top-[150px]"></a>
        <button type="button" class="block w-full py-[15px] text-left btn-toggle-panel">
            <h2 class="w-full px-[1.31vw] leading-[1em] typog-title"><?php esc_attr_e('Perfil','amrwp'); ?></h2>
        </button>
        <div class="toggle-panel">
            <div class="md:flex md:flex-wrap">
                <div class="md:w-[60.75%]">
                    <form action="" class="form-edit-user-profile" data-action="amrwp_form_profile_edit" data-nonce="<?php echo wp_create_nonce("amrwp_form_profile_edit_nonce"); ?>">
                        <div class="px-[15px] md:px-[1.97vw] py-[15px] mt-[30px] form-row">
                            <button type="button" class="btn-edit-field"><?php esc_attr_e('Editar','amrwp'); ?></button>
                            <label class="field-label" for="perfilnome"><?php esc_attr_e('Nome','amrwp'); ?></label>
                            <input required="required" class="field-to-edit" <?php if ( isset($user_first_name) ) { echo 'value="' . $user_first_name . '"'; } ?> placeholder="<?php esc_attr_e('Preencha com seu primeiro nome','amrwp'); ?>" disabled="disabled" type="text" id="perfilnome" name="perfilnome">
                            <div class="mt-[10px] flex gap-x-[20px] justify-end submit-buttons">
                                <button type="button" class="btn-cancel-edit"><?php esc_attr_e('Cancelar','amrwp'); ?></button> <button type="submit">Salvar</button>
                            </div>
                            <div class="form-msg form-error-msg"></div>
                            <div data-msg="<?php esc_attr_e('Nome atualizado com sucesso!','amrwp'); ?>" class="form-msg form-success-msg"></div>
                        </div>
                        <!-- /.form-row -->
                    </form>
                    <form action="" class="form-edit-user-profile" data-action="amrwp_form_profile_edit" data-nonce="<?php echo wp_create_nonce("amrwp_form_profile_edit_nonce"); ?>">
                        <div class="px-[15px] md:px-[1.97vw] py-[15px] mt-[10px] form-row">
                            <button type="button" class="btn-edit-field"><?php esc_attr_e('Editar','amrwp'); ?></button>
                            <label class="field-label" for="perfilsobrenome"><?php esc_attr_e('Sobrenome','amrwp'); ?></label>
                            <input required="required" class="field-to-edit" <?php if ( isset($user_last_name) ) { echo 'value="' . $user_last_name . '"'; } ?> placeholder="<?php esc_attr_e('Preencha com seu sobrenome','amrwp'); ?>" disabled="disabled" type="text" id="perfilsobrenome" name="perfilsobrenome">
                            <div class="mt-[10px] flex gap-x-[20px] justify-end submit-buttons">
                                <button type="button" class="btn-cancel-edit"><?php esc_attr_e('Cancelar','amrwp'); ?></button> <button type="submit">Salvar</button>
                            </div>
                            <div class="form-msg form-error-msg"></div>
                            <div data-msg="<?php esc_attr_e('Sobrenome atualizado com sucesso!','amrwp'); ?>" class="form-msg form-success-msg"></div>
                        </div>
                        <!-- /.form-row -->
                    </form>
                    <form action="" class="form-edit-user-profile" data-action="amrwp_form_profile_edit" data-nonce="<?php echo wp_create_nonce("amrwp_form_profile_edit_nonce"); ?>">
                        <div class="px-[15px] md:px-[1.97vw] py-[15px] mt-[10px] form-row">
                            <button type="button" class="btn-edit-field"><?php esc_attr_e('Editar','amrwp'); ?></button>
                            <label class="field-label" for="perfilemail"><?php esc_attr_e('E-mail','amrwp'); ?></label>
                            <input required="required" class="field-to-edit" <?php if ( isset($user_email) ) { echo 'value="' . $user_email . '"'; } ?> placeholder="<?php esc_attr_e('Preencha com seu e-mail','amrwp'); ?>" disabled="disabled" type="email" id="perfilemail" name="perfilemail">
                            <div class="mt-[10px] flex gap-x-[20px] justify-end submit-buttons">
                                <button type="button" class="btn-cancel-edit"><?php esc_attr_e('Cancelar','amrwp'); ?></button> <button type="submit">Salvar</button>
                            </div>
                            <div class="form-msg form-error-msg"></div>
                            <div data-msg="<?php esc_attr_e('E-mail atualizado com sucesso!','amrwp'); ?>" class="form-msg form-success-msg"></div>
                        </div>
                        <!-- /.form-row -->
                    </form>
                    <form action="" class="form-edit-user-profile" data-action="amrwp_form_profile_edit" data-nonce="<?php echo wp_create_nonce("amrwp_form_profile_edit_nonce"); ?>">
                        <div class="px-[15px] md:px-[1.97vw] py-[15px] mt-[10px] form-row">
                            <button type="button" class="btn-edit-field"><?php esc_attr_e('Trocar','amrwp'); ?></button>
                            <label class="field-label" for="perfilsenha"><?php esc_attr_e('Senha','amrwp'); ?></label>
                            <input required="required" class="field-to-edit" value="*******" placeholder="<?php esc_attr_e('Digite uma senha','amrwp'); ?>" disabled="disabled" type="password" id="perfilsenha" name="perfilsenha">
                            <div class="mt-[10px] flex gap-x-[20px] justify-end submit-buttons">
                                <button type="button" class="btn-cancel-edit"><?php esc_attr_e('Cancelar','amrwp'); ?></button> <button type="submit"><?php esc_attr_e('Salvar','amrwp'); ?></button>
                            </div>
                            <div class="form-msg form-error-msg"></div>
                            <div class="form-password-change-msg" data-msg="<?php esc_attr_e('Senha atualizada com sucesso!','amrwp'); ?>" class="form-msg form-success-msg"></div>
                        </div>
                        <!-- /.form-row -->
                    </form>
                </div>
                <div class="md:ml-auto md:w-[34.9%]">
                    <form action="" class="form-add-profile-image">
                        <input type="hidden" name="formnonce" value="<?php echo wp_create_nonce("amrwp_form_profile_image_nonce"); ?>">
                        <input type="hidden" name="action" value="amrwp_form_profile_image">
                        <div class="px-[1.9vw] md:mt-[30px] pt-[30px] md:pt-[15px] form-row <?php if ( ! get_user_meta( $user_info->ID, 'amr_user_profile_img', true ) ) { ?>no-image<?php } ?>">
                            <div class="flex">
                                <p class="text-[14px]"><?php esc_attr_e('Imagem do Perfil','amrwp'); ?></p>
                                <button class="ml-auto btn-edit-profile-image" type="button">Editar</button>
                            </div>
                            <div class="user-image pt-[5px]">
                                <div class="relative profile-image" data-user-id="<?php echo $user_info->ID; ?>">
                                    <?php
                                    $profile_image = public_url() . 'images/user-no-photo.svg';
                                    if ( get_user_meta( $user_info->ID, 'amr_user_profile_img', true ) ) {
                                        $profile_image = get_user_meta( $user_info->ID, 'amr_user_profile_img', true );
                                    } else { ?>
                                        <button class="btn-add-profile-image" title="<?php esc_attr_e('Adicionar imagem de perfil','amrwp'); ?>" type="button"></button>
                                    <?php } ?>
                                    <img src="<?php echo $profile_image; ?>" alt="" width="180" height="180" class="block profile-image-element">
                                </div>
                                <div class="mt-[10px] py-[10px] flex flex-wrap gap-y-[10px] gap-x-[20px] justify-center submit-buttons">
                                    <div class="w-full">
                                        <input name="perfilimagem" type="file" accept=".png, .jpg, .jpeg" placeholder="<?php esc_attr_e('Selecione o arquivo','amrwp'); ?>">
                                    </div>
                                    <button type="button" class="btn-cancel-edit"><?php esc_attr_e('Cancelar','amrwp'); ?></button> <button type="submit"><?php esc_attr_e('Salvar','amrwp'); ?></button>
                                </div>
                            </div>
                            <div class="form-msg form-error-msg"></div>
                            <div data-msg="<?php esc_attr_e('Imagem de perfil atualizada com sucesso!','amrwp'); ?>" class="py-[10px] form-msg form-success-msg"></div>
                        </div>
                    </form>
                </div>
                <section class="mt-[40px] flex flex-wrap pb-[60px]">
                    <h3 class="w-full leading-[1em] typog-title-med"><?php esc_attr_e('Endereço de faturamento','amrwp'); ?></h3>
                    <div class="md:w-[60.75%]">
                        <form action="" class="form-edit-user-shipping">
                            <input type="hidden" name="formnonce" value="<?php echo wp_create_nonce("amrwp_form_profile_address_nonce"); ?>">
                            <input type="hidden" name="action" value="amrwp_form_profile_address">
                            <div class="form-field mt-[40px]">
                                <?php
                                    global $woocommerce;
                                    $user_country = $woocommerce->customer->get_billing_country();
                                    $user_postcode = $woocommerce->customer->get_billing_postcode();
                                    $user_address_1 = $woocommerce->customer->get_billing_address_1();
                                    $user_address_2 = $woocommerce->customer->get_billing_address_2();
                                    $user_city = $woocommerce->customer->get_billing_city();
                                    $user_state = $woocommerce->customer->get_billing_state();
                                    $user_address_2 = $woocommerce->customer->get_billing_address_2();
                                    $user_number = $woocommerce->customer->get_meta( 'billing_number' );
                                ?>
                                <label class="block mb-[10px]" for="entregapais"><?php esc_attr_e('País','amrwp'); ?></label>
                                <select name="entregapais" id="entregapais">
                                    <option value=""><?php esc_attr_e('Selecione um país','amrwp'); ?></option>
                                    <?php
                                    include_once( 'includes/paises-array.php' );
                                    foreach ($paises_lista as $pais) {
                                    ?>
                                    <option <?php if ( isset($user_country) && ! empty($user_country) && $user_country == $pais['sigla2'] ) { echo 'selected="selected"'; } ?> value="<?php echo $pais['sigla2']; ?>"><?php echo $pais['nome']; ?></option>
                                    <?php
                                    }
                                    ?>
                                </select>
                            </div>
                            <div class="form-field mt-[40px] form-field-cep">
                                <label class="block mb-[10px]" for="entregacep"><?php esc_attr_e('CEP / Código Postal','amrwp'); ?></label>
                                <input type="text" name="entregacep" id="entregacep" <?php if ( isset($user_postcode) && ! empty($user_postcode) ) { echo 'value="' . $user_postcode . '"'; }  ?>>
                                <p class="py-[10px] form-msg-error"><?php esc_attr_e('CEP inválido!','amrwp'); ?></p>
                            </div>
                            <div class="form-field mt-[40px]">
                                <label class="block mb-[10px]" for="entregalogradouro"><?php esc_attr_e('Rua ou Avenida','amrwp'); ?></label>
                                <input readonly="readonly" type="text" name="entregalogradouro" id="entregalogradouro" <?php if ( isset($user_address_1) && ! empty($user_address_1) ) { echo 'value="' . $user_address_1 . '"'; }  ?>>
                            </div>
                            <div class="form-field mt-[40px] flex">
                                <div class="w-[30%]">
                                    <label class="block mb-[10px]" for="entreganumero"><?php esc_attr_e('Número','amrwp'); ?></label>
                                    <input type="text" name="entreganumero" id="entreganumero" <?php if ( isset($user_number) && ! empty($user_number) ) { echo 'value="' . $user_number . '"'; }  ?>>
                                </div>
                                <div class="w-[40%] ml-[20px]">
                                    <label class="block mb-[10px]" for="entregacomplemento"><?php esc_attr_e('Complemento','amrwp'); ?></label>
                                    <input type="text" name="entregacomplemento" id="entregacomplemento" <?php if ( isset($user_address_2) && ! empty($user_address_2) ) { echo 'value="' . $user_address_2 . '"'; }  ?>>
                                </div>
                            </div>
                            <div class="form-field mt-[40px] flex">
                                <div class="w-[40%]">
                                    <label class="block mb-[10px]" for="entregacidade"><?php esc_attr_e('Cidade','amrwp'); ?></label>
                                    <input readonly="readonly" type="text" name="entregacidade" id="entregacidade" <?php if ( isset($user_city) && ! empty($user_city) ) { echo 'value="' . $user_city . '"'; }  ?>>
                                </div>
                                <div class="ml-[20px]">
                                    <label class="block mb-[10px]" for="entregaestado"><?php esc_attr_e('Estado (UF)','amrwp'); ?></label>
                                    <input readonly="readonly" type="text" name="entregaestado" id="entregaestado" <?php if ( isset($user_state) && ! empty($user_state) ) { echo 'value="' . $user_state . '"'; }  ?>>
                                </div>
                            </div>
                            <div class="mt-[40px] form-msg form-all-error-msg" data-invalidos="<?php esc_attr_e('Existem alguns campos inválidos ou não preenchidos, verifique e tente novamente.','amrwp'); ?>"></div>
                            <div class="mt-[40px] form-msg form-success-msg" data-msg="<?php esc_attr_e('Endereço de entrega atualizado com sucesso!','amrwp'); ?>"></div>
                            <div class="form-submit form-field mt-[40px]">
                                <button class="max-w-[160px]" type="submit"><?php esc_attr_e('Atualizar endereço','amrwp'); ?></button>
                            </div>
                        </form>
                    </div>
                </section>

            </div>
        </div>

    </section>

    <section class="mt-[40px] pb-[60px]">
        <a name="meus-programas"></a>
    <?php
$courses_qry = new WP_Query(array(
    'post_type' => 'course',
    'posts_per_page' => -1,
    'orderby' => 'menu_order',
    'order' => 'ASC'
));

if ( $courses_qry->have_posts() ): 
?>
<button type="button" class="block w-full py-[15px] text-left btn-toggle-panel active">
    <h2 class="w-full px-[1.31vw] leading-[1em] typog-title"><?php esc_attr_e('Meus programas','amrwp'); ?></h2>
</button>
<div class="toggle-panel" style="display:none;">

    <p class="px-[1.31vw] mt-[20px] mb-[20px]">Clique no programa que deseja acessar:</p>
    <div class="wp-programas-acompanhamento">

    <?php
    while ( $courses_qry->have_posts() ): $courses_qry->the_post();
        $post = get_post( get_the_ID() );

        $pages_pgms = get_posts(array(
            'numberposts' => 1,
            'post_type' => 'page',
            'meta_key' => 'pgm_crs_rlcd',
            'meta_value' => get_the_ID()
        ));
        if ( $pages_pgms ) {
            $page_link = get_permalink( $pages_pgms[0]->ID );
        }

    ?>
    <article <?php post_class( 'wp-course-post' ); ?>>
    <?php
    if ( isset( $page_link ) && amrwp_can_user_access_content(get_the_ID()) ) {
    ?>
    <a href="<?php echo $page_link; ?>">
    <?php
    }
    if ( has_post_thumbnail() ) {
        the_post_thumbnail( 'full' );
    }
    ?>
    <div class="wp-course-info">
        <h2 class="wp-post-title"><?php the_title(); ?></h2>
        <div class="wp-post-excerpt">
            <?php echo $post->post_excerpt; ?>
        </div>
        <!-- /.wp-post-excerpt -->
    <?php
    if ( isset( $page_link ) && amrwp_can_user_access_content(get_the_ID()) ) {
    ?>
    </a>
    <?php
    }
    ?>
    </div>
    <!-- /.wp-course-info -->
    
    </article>
    <?php
    ?>
    <?php
    endwhile;
    ?>
</div>
<!-- /.wp-programas-acompanhamento -->
</div>
<?php
endif;
?>
    </section>

</section>
<!-- /.page-content-wrapper -->

<?php get_footer(); ?>