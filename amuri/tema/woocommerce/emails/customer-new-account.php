<?php
/**
 * Customer new account email
 *
 * This template can be overridden by copying it to yourtheme/woocommerce/emails/customer-new-account.php.
 *
 * HOWEVER, on occasion WooCommerce will need to update template files and you
 * (the theme developer) will need to copy the new files to your theme to
 * maintain compatibility. We try to do this as little as possible, but it does
 * happen. When this occurs the version of the template file will be bumped and
 * the readme will list any important changes.
 *
 * @see https://woo.com/document/template-structure/
 * @package WooCommerce\Templates\Emails
 * @version 6.0.0
 */

defined( 'ABSPATH' ) || exit;

do_action( 'woocommerce_email_header', $email_heading, $email ); ?>

<?php /* translators: %s: Customer username */ ?>
<p><?php printf( esc_html__( 'Olá %s,', 'amrwp' ), esc_html( $user_login ) ); ?></p>
<?php /* translators: %1$s: Site title, %2$s: Username, %3$s: My account link */ ?>
<p style="margin-top:15px;"><?php // printf( esc_html__( 'Thanks for creating an account on %1$s. Your username is %2$s. You can access your account area to view orders, change your password, and more at: %3$s', 'woocommerce' ), esc_html( $blogname ), '<strong>' . esc_html( $user_login ) . '</strong>', make_clickable( esc_url( wc_get_page_permalink( 'myaccount' ) ) ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></p>
<p style="margin-top:15px;"><?php esc_attr_e( 'Deu tudo certo com a criação da sua conta.', 'amrwp' ); ?></p>
<?php if ( 'yes' === get_option( 'woocommerce_registration_generate_password' ) && $password_generated && $set_password_url ) : ?>
	<?php // If the password has not been set by the user during the sign up process, send them a link to set a new password ?>
	<p style="margin-top:15px;"><?php esc_attr_e('Uma senha provisória foi criada e você deve alterá-la','amrwp'); ?> <a href="<?php echo esc_attr( $set_password_url ); ?>"><?php printf( esc_html__( 'clicando aqui→', 'amrwp' ) ); ?></a>.</p>
<?php endif; ?>
<p style="margin-top:15px;"><?php printf( esc_html__( 'Nas próximas vezes, você pode acessar a plataforma diretamente, através desse link: %s', 'amrwp' ), make_clickable( esc_url( "https://programas.amuri.com.br/meus-programas/" ) ) ); ?></p>
<p style="margin-top:15px;"><?php esc_attr_e('Nos vemos em breve!','amrwp'); ?> <br><?php esc_attr_e('Um abraço grande,','amrwp'); ?><br> <?php esc_attr_e('Amuri','amrwp'); ?></p>
<?php
/**
 * Show user-defined additional content - this is set in each email's settings.
 */
if ( $additional_content ) {
	// echo wp_kses_post( wpautop( wptexturize( $additional_content ) ) );
}

do_action( 'woocommerce_email_footer', $email );
