<?php
/**
 * Thankyou page
 *
 * This template can be overridden by copying it to yourtheme/woocommerce/checkout/thankyou.php.
 *
 * HOWEVER, on occasion WooCommerce will need to update template files and you
 * (the theme developer) will need to copy the new files to your theme to
 * maintain compatibility. We try to do this as little as possible, but it does
 * happen. When this occurs the version of the template file will be bumped and
 * the readme will list any important changes.
 *
 * @see https://woo.com/document/template-structure/
 * @package WooCommerce\Templates
 * @version 8.1.0
 *
 * @var WC_Order $order
 */

defined( 'ABSPATH' ) || exit;
?>

<div class="woocommerce-order">

	<?php
	if ( $order ) :

		do_action( 'woocommerce_before_thankyou', $order->get_id() );
		?>

		<?php if ( $order->has_status( 'failed' ) ) : ?>

			<p class="woocommerce-notice woocommerce-notice--error woocommerce-thankyou-order-failed"><?php esc_html_e( 'Ops! Não conseguimos concluir seu pagamento — o banco não autorizou a transação. Pode ser falta de limite, cartão bloqueado ou algum dado incorreto. Você pode tentar novamente com o mesmo cartão ou com outro.', 'amrwp' ); ?></p>

			<p class="woocommerce-notice woocommerce-notice--error woocommerce-thankyou-order-failed-actions">
				<a href="<?php echo esc_url( $order->get_checkout_payment_url() ); ?>" class="button pay"><?php esc_html_e( 'Tentar pagar novamente', 'amrwp' ); ?></a>
				<?php if ( is_user_logged_in() ) : ?>
					<a href="<?php echo esc_url( wc_get_page_permalink( 'myaccount' ) ); ?>" class="button pay"><?php esc_html_e( 'Minha conta', 'amrwp' ); ?></a>
				<?php endif; ?>
			</p>

		<?php else : ?>

			<?php wc_get_template( 'checkout/order-received.php', array( 'order' => $order ) ); ?>

			<ul class="woocommerce-order-overview woocommerce-thankyou-order-details order_details">

				<li class="woocommerce-order-overview__order order">
					<?php esc_html_e( 'Order number:', 'woocommerce' ); ?>
					<strong><?php echo $order->get_order_number(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></strong>
				</li>

				<li class="woocommerce-order-overview__date date">
					<?php esc_html_e( 'Date:', 'woocommerce' ); ?>
					<strong><?php echo wc_format_datetime( $order->get_date_created() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></strong>
				</li>

				<?php if ( is_user_logged_in() && $order->get_user_id() === get_current_user_id() && $order->get_billing_email() ) : ?>
					<li class="woocommerce-order-overview__email email">
						<?php esc_html_e( 'Email:', 'woocommerce' ); ?>
						<strong><?php echo $order->get_billing_email(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></strong>
					</li>
				<?php endif; ?>

				<li class="woocommerce-order-overview__total total">
					<?php esc_html_e( 'Total:', 'woocommerce' ); ?>
					<strong><?php echo $order->get_formatted_order_total(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></strong>
				</li>

				<?php if ( $order->get_payment_method_title() ) : ?>
					<li class="woocommerce-order-overview__payment-method method">
						<?php esc_html_e( 'Payment method:', 'woocommerce' ); ?>
						<strong><?php echo wp_kses_post( $order->get_payment_method_title() ); ?></strong>
					</li>
				<?php endif; ?>

			</ul>

			<div class="woocommerce-thankyou-page-messages">
				<div class="woocommerce-thankyou-page-message">
					<p>
						<?php esc_attr_e('Que alegria saber que seguiremos juntos! ','amrwp'); ?>
					</p><p>

						<b><?php esc_attr_e('Uma senha provisória foi criada e você pode acessar a plataforma para alterá-la ','amrwp'); ?></b>

						<a href="https://programas.amuri.com.br/editar-perfil/"><?php printf( esc_html__( 'clicando aqui→', 'amrwp' ) ); ?></a>.
					</p>
					<p>
						Se não tiver tempo para fazer isso agora não tem problema. Todas as informações foram enviadas para seu email 🙂
					</p>
					<p class="woocommerce-thankyou-page-message-actions">
						<a href="<?php echo esc_url( amrwp_plataforma_url( 'meus-programas/' ) ); ?>" class="button pay"><?php esc_attr_e( 'Entrar na plataforma!', 'amrwp' ); ?></a>
					</p>
				</div>

				<div class="woocommerce-thankyou-page-message">
					<p><?php printf( esc_html__('Se você tiver qualquer dúvida, me escreva através do %s!', 'amrwp' ), 'eduardo@amuri.com.br' ); ?></p>
					<p><?php esc_attr_e('Um abraço grande e seguimos,','amrwp'); ?><br> Amuri</p>
				</div>
			</div>

		<?php endif; ?>

	<?php else : ?>

		<?php wc_get_template( 'checkout/order-received.php', array( 'order' => false ) ); ?>

	<?php endif; ?>

</div>
