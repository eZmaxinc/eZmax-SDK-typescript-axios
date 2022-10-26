/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The Ezmaxinvoicing payment type
 * @export
 * @enum {string}
 */

export const FieldEEzmaxinvoicingPaymenttype = {
    Cheque: 'Cheque',
    CreditCard: 'CreditCard',
    DirectDebit: 'DirectDebit'
} as const;

export type FieldEEzmaxinvoicingPaymenttype = typeof FieldEEzmaxinvoicingPaymenttype[keyof typeof FieldEEzmaxinvoicingPaymenttype];



