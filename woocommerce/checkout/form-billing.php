<?php
/**
 * Checkout billing information form (override)
 *
 * Original template copied from WooCommerce 3.6.0.
 * Reorganizado em dois grupos: "Meus dados" e "Endereço".
 *
 * @see     https://woocommerce.com/document/template-structure/
 * @package WooCommerce\Templates
 * @version 3.6.0
 * @global WC_Checkout $checkout
 */

defined( 'ABSPATH' ) || exit;

$amrwp_personal_keys = array(
	'billing_first_name',
	'billing_last_name',
	'billing_email',
	'billing_cpf',
	'billing_phone',
);

$amrwp_address_keys = array(
	'billing_postcode',
	'billing_country',
	'billing_address_1',
	'billing_number',
	'billing_address_2',
	'billing_neighborhood',
	'billing_city',
	'billing_state',
);

$amrwp_billing_fields = $checkout->get_checkout_fields( 'billing' );
?>
<div class="woocommerce-billing-fields">

	<?php do_action( 'woocommerce_before_checkout_billing_form', $checkout ); ?>

	<div class="woocommerce-billing-fields__group woocommerce-billing-fields__group--personal">
		<div class="woocommerce-billing-fields__field-wrapper">
			<?php
			foreach ( $amrwp_personal_keys as $amrwp_key ) {
				if ( isset( $amrwp_billing_fields[ $amrwp_key ] ) ) {
					woocommerce_form_field( $amrwp_key, $amrwp_billing_fields[ $amrwp_key ], $checkout->get_value( $amrwp_key ) );
				}
			}
			?>
		</div>
	</div>

	<div class="woocommerce-billing-fields__group woocommerce-billing-fields__group--address">
		<h3><?php esc_html_e( 'Quase lá, agora seu endereço!', 'amuri' ); ?></h3>

		<div class="woocommerce-billing-fields__field-wrapper">
			<?php
			foreach ( $amrwp_address_keys as $amrwp_key ) {
				if ( isset( $amrwp_billing_fields[ $amrwp_key ] ) ) {
					woocommerce_form_field( $amrwp_key, $amrwp_billing_fields[ $amrwp_key ], $checkout->get_value( $amrwp_key ) );
				}
			}

			// Render any additional billing field not explicitly grouped above, so custom fields from plugins still appear.
			foreach ( $amrwp_billing_fields as $amrwp_key => $amrwp_field ) {
				if ( in_array( $amrwp_key, $amrwp_personal_keys, true ) || in_array( $amrwp_key, $amrwp_address_keys, true ) ) {
					continue;
				}
				woocommerce_form_field( $amrwp_key, $amrwp_field, $checkout->get_value( $amrwp_key ) );
			}
			?>
		</div>
	</div>

	<?php do_action( 'woocommerce_after_checkout_billing_form', $checkout ); ?>
</div>

<?php if ( ! is_user_logged_in() && $checkout->is_registration_enabled() ) : ?>
	<div class="woocommerce-account-fields">
		<?php if ( ! $checkout->is_registration_required() ) : ?>

			<p class="form-row form-row-wide create-account">
				<label class="woocommerce-form__label woocommerce-form__label-for-checkbox checkbox">
					<input class="woocommerce-form__input woocommerce-form__input-checkbox input-checkbox" id="createaccount" <?php checked( ( true === $checkout->get_value( 'createaccount' ) || ( true === apply_filters( 'woocommerce_create_account_default_checked', false ) ) ), true ); ?> type="checkbox" name="createaccount" value="1" /> <span><?php esc_html_e( 'Create an account?', 'woocommerce' ); ?></span>
				</label>
			</p>

		<?php endif; ?>

		<?php do_action( 'woocommerce_before_checkout_registration_form', $checkout ); ?>

		<?php if ( $checkout->get_checkout_fields( 'account' ) ) : ?>

			<div class="create-account">
				<?php foreach ( $checkout->get_checkout_fields( 'account' ) as $key => $field ) : ?>
					<?php woocommerce_form_field( $key, $field, $checkout->get_value( $key ) ); ?>
				<?php endforeach; ?>
				<div class="clear"></div>
			</div>

		<?php endif; ?>

		<?php do_action( 'woocommerce_after_checkout_registration_form', $checkout ); ?>
	</div>
<?php endif; ?>
