<div class="header-user-menu flex justify-end">
    <button class="user-photo toggle-user-menu">
<?php
$user = wp_get_current_user();
if ( isset( $user->ID ) ) {
    $profile_image = public_url() . 'images/user-no-photo.svg';
    if ( get_user_meta( $user->ID, 'amr_user_profile_img', true ) ) {
        $profile_image = get_user_meta( $user->ID, 'amr_user_profile_img', true );
    }
    ?>
    <div class="user-image">
        <img src="<?php echo $profile_image; ?>" width="39" height="39" alt="" class="user-menu-image-element">
    </div>
<?php
}
?>
    </button>
</div>