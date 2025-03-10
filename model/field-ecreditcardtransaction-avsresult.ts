/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The result for the address validation
 * @export
 * @enum {string}
 */

export const FieldECreditcardtransactionAvsresult = {
    Match: 'Match',
    NoMatch: 'NoMatch',
    PartialMatch: 'PartialMatch',
    NotImplemented: 'NotImplemented',
    NotVerified: 'NotVerified'
} as const;

export type FieldECreditcardtransactionAvsresult = typeof FieldECreditcardtransactionAvsresult[keyof typeof FieldECreditcardtransactionAvsresult];



