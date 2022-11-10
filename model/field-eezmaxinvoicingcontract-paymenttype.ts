/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The Ezmaxinvoicingcontract payment type
 * @export
 * @enum {string}
 */

export const FieldEEzmaxinvoicingcontractPaymenttype = {
    Cheque: 'Cheque',
    CreditCard: 'CreditCard',
    DirectDebit: 'DirectDebit'
} as const;

export type FieldEEzmaxinvoicingcontractPaymenttype = typeof FieldEEzmaxinvoicingcontractPaymenttype[keyof typeof FieldEEzmaxinvoicingcontractPaymenttype];



