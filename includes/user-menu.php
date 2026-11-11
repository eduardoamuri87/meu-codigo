<?php
$user = wp_get_current_user();
if ( isset( $user->ID ) ) {
    $profile_image = public_url() . 'images/user-no-photo.svg';
    if ( get_user_meta( $user->ID, 'amr_user_profile_img', true ) ) {
        $profile_image = get_user_meta( $user->ID, 'amr_user_profile_img', true );
    }
}
?>
<div class="bg-white flex flex-col fixed z-900 top-0 right-0 mxmd:w-screen md:w-[26vw] h-screen mxmd:pt-[8.33vh] md:pt-[10vh] pb-[5vh] px-[4vw] translate-x-full user-menu-container">
    <button class="mxmd:hidden absolute rotate-[180deg] right-[3vw] top-[4vh] toggle-user-menu w-[40px] h-[40px] flex justify-center items-center"><span class="sr-only"><?php esc_attr_e('Expandir/Contrair o menu','amrwp'); ?></span>
        <svg version="1.1" id="Layer_5" xmlns="http://www.w3.org/2000/svg" x="0" y="0" width="8" height="14.002" style="enable-background:new 0 0 8 14.002" xml:space="preserve"><path d="M.293 6.295a1 1 0 0 0 0 1.415l5.999 5.999a1 1 0 1 0 1.415-1.415L2.414 7.001l5.29-5.293A1 1 0 1 0 6.289.293L.29 6.292l.003.003z" style="fill:#2d313f"/></svg>
    </button>
    <button class="md:hidden mxmd:absolute mxmd:right-[8.33vw] mxmd:top-[6.66vh] btn-close toggle-user-menu w-[40px] h-[40px] flex justify-center items-center"><span class="ball"></span><span class="sr-only"><?php esc_attr_e('Fechar o menu mobile','amrwp'); ?></span></button>
    <?php
    if ( isset( $profile_image ) ) { ?>
    <div class="user-image">
        <img src="<?php echo $profile_image; ?>?img=profille" width="116" height="116" alt="" class="user-menu-image-element">
    </div>
    <?php } ?>
    <p class="mt-[25px] text-center typog-title user-menu-first-last-names"><?php echo amrwp_get_users_first_last_name(); ?></p>
    <?php
    if ( has_nav_menu( 'user-menu' ) ) {
    ?>
        <nav id="site-navigation-user-menu" class="mt-[5vh] mxmd:mb-[20px] md:mb-[3.33vh] user-menu-wrapper" aria-label="<?php esc_attr_e( 'Menu do usuário', 'amrwp' ); ?>">
        <?php
            wp_nav_menu( array(
                'theme_location' => 'user-menu',
                'menu_class'     => 'flex flex-col user-menu-items',
                'container'     => '',
            ) );
        ?>
    </nav>
    <?php
        }
    ?>
    <a href="<?php echo get_permalink(167); ?>" class="go-to-my-programas typog-title mt-auto flex items-center leading-1em"><?php esc_attr_e('Acessar plataforma','amrwp'); ?> 
    <a href="<?php echo wp_logout_url( get_permalink( get_option('woocommerce_myaccount_page_id') ) ); ?>" class="mt-[30px] typog-title flex items-center leading-1em logout-link"><?php esc_attr_e('Logout','amrwp'); ?> 
        <svg class="ml-[10px] mb-[5px]" version="1.1" id="Layer_5" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px"
	 width="17.147px" height="15.004px" viewBox="0 0 17.147 15.004" style="enable-background:new 0 0 17.147 15.004;"
	 xml:space="preserve">
            <path class="st2" d="M16.833,8.259c0.419-0.419,0.419-1.099,0-1.517l-4.287-4.287c-0.419-0.419-1.099-0.419-1.517,0
	s-0.419,1.099,0,1.517l2.458,2.458H6.43c-0.593,0-1.072,0.479-1.072,1.072c0,0.593,0.479,1.072,1.072,1.072h7.057l-2.458,2.458
	c-0.419,0.419-0.419,1.099,0,1.517c0.419,0.419,1.099,0.419,1.517,0l4.287-4.287V8.259z M5.359,2.143
	c0.593,0,1.072-0.479,1.072-1.072S5.952,0,5.359,0H3.215C1.44,0,0,1.44,0,3.215v8.574c0,1.775,1.44,3.215,3.215,3.215h2.143
	c0.593,0,1.072-0.479,1.072-1.072s-0.479-1.072-1.072-1.072H3.215c-0.593,0-1.072-0.479-1.072-1.072V3.215
	c0-0.593,0.479-1.072,1.072-1.072H5.359z"/>
        </svg>
    </a>
</div>
